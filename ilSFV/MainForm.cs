﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data.SqlServerCe;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using ilSFV.Hash;
using ilSFV.Localization;
using ilSFV.Model.Settings;
using ilSFV.Model.Workset;
using ilSFV.Tools;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Timer = System.Windows.Forms.Timer;

namespace ilSFV
{
    public sealed partial class MainForm : Form
    {
        // TODO: PRI 0
        // TODO: comments font selection; see http://discuss.big-o-software.com/viewtopic.php?f=3&t=204
        // TODO: comment template by format (md5/sha1/sfv)
        // TODO: Results file: cSFVse; see http://discuss.big-o-software.com/viewtopic.php?f=3&t=1046 - called "Result Logs", http://discuss.big-o-software.com/viewtopic.php?f=3&t=4632
        // TODO: Support to create checksums of Read-only folders (e.g. CDROM) and save the checksum in a different folder

        // - Drag'n'Drop support for Folders (recursive) and mixed selected folders/files.
        // - Creation of Checksum File via context menu with recursive / subdirectory support
        // - Check for long filenames / folder names and skip those files with correct error msg (at the moment ilsfv does not accept drag'n'drop of files with path longer than 250 characters)
        // When you have multiple directory sfv creattion (create file in each subdirectory) and prompt for file name, successive prompts should be appear (so that all files are not named the same)
        // an option (auto replace sfv in directory) would be nice.
        // And a new sfv file created should use the cache for faster creation (in case the same files have already been checked).
        // queue the creation of multiple SFV files.
        // optimze for 64 bit

        /*
double click item to open containing folder
checksum auto formatting.. 00-{0}.sfv where {0} = dir name - http://img4.imageshack.us/img4/9409/clipboard15u.jpg
compare to cSFV http://cruzer.antispam.dk/csfv/versionhistory.php
ensure overwrite +r
export results to text file
         */

        // TODO: PRI 1
        // TODO: upper/lower case checksum, per format
        // TODO: show current cache size
        // TODO: add tick marks to list view items (which items to check)
        // TODO: command line support
        // TODO: empty folder on verify: Something like this when passed: [100% Complete]-[#30 files OK] and when not passed: [80% Complete]-[#27 files OK - #2 Bads - 1 Missing] 
        // TODO: hash in filename (regex?)
        // TODO: utf8/codepage

        // TODO: PRI 2
        // TODO: Shell, get checksum of files without creating .sfv file
        // TODO: Shell extension (allows you to select files in explorer to check, or to create an .SFV or .MD5 for)
        // TODO: Shell, recursively check directories
        // TODO: Shell, allow user to specify if they want shell extensions nested in submenu
        // TODO: Shell terms "Context menu handler", "QueryInfo handler"
        // TODO: restores previous file associations when you uninstall
        // TODO: fix file association when other programs steal it
        // TODO: Explorer Info Tooltip (Files in SFV: 12)
        // TODO: intelligent sorting, ex, Flex9 before Flex10, '9 - abc' before '10 - abc'
        // TODO: md5sum detailed compatibility: http://discuss.big-o-software.com/viewtopic.php?f=2&t=5441 use # for comments, \n only for newline

        // TODO: PRI 3
        // TODO: Multilingual support
        // TODO: PAR/PAR2 (see program FSRaid, avoid mirror and smartpar)

        public const int CODE_PAGE = 1252;

        [DllImport("user32")]
        private static extern bool SendMessage(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

        private const uint LVM_SETTEXTBKCOLOR = 0x1026;

        [DllImport("user32.dll")]
        private static extern bool FlashWindow(IntPtr hwnd, bool bInvert);
        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        private readonly List<ChecksumSet> _sets = new List<ChecksumSet>();
        private bool _workingOnList;
        private bool _queueHideGood;
        private bool _queueStop;

        private readonly bool _initialVerify;
        private readonly bool _initialCreate;
        private readonly ChecksumType _initialCreateChecksumType;
        private readonly Timer _timer;
        private readonly FileSystemWatcher _fsw;

        public void PlayCompleteSound(bool allOK)
        {
            if (allOK)
            {
                if (!Program.Settings.Check.PlaySoundOK)
                    return;

                if (Program.Settings.Check.PlaySoundOK_OnlyIfInactive && GetForegroundWindow() == Handle)
                    return;
            }
            else
            {
                if (!Program.Settings.Check.PlaySoundError)
                    return;
            }

            try
            {
                string shortFileName = string.Format("complete_{0}.wav", allOK ? "ok" : "error");
                string completeWav = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), shortFileName);
                if (File.Exists(completeWav))
                {
                    Sound.PlaySound(completeWav, IntPtr.Zero, Sound.SoundFlags.SND_FILENAME | Sound.SoundFlags.SND_ASYNC);
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex);
            }
        }

        public MainForm(string[] args)
        {
            InitializeComponent();

            tpQuickSFV.Parent = null; // hide tab

            Language.Changed += delegate { SetLanguage(); };
            SetLanguage();

            //miFindRenamedFiles.Visible = false;
            //miTruncateFileNames.Visible = false;
            //toolStripSeparator6.Visible = false;

            _fsw = new FileSystemWatcher(Program.AppDataPath, "*.add");
            _fsw.Created += _fsw_Created;
            _fsw.EnableRaisingEvents = true;

            notifyIcon1.BalloonTipClicked += notifyIcon1_BalloonTipClicked;

            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            int major = version.Major;
            int minor = version.Minor;
            int build = version.Build;

            Text = string.Format("ilSFV {0}.{1}", major, minor, build);

            ResizeStatusBar();

            chkHideGood.Checked = Program.Settings.General.HideGoodFiles;
            miHideGood.Checked = Program.Settings.General.HideGoodFiles;
            miUseCachedResults.Checked = Program.Settings.General.UseCachedResults;
            miFindRenamedFiles.Enabled = false;

            btnPause.Enabled = false;
            btnHide.Enabled = false;

            if (Program.Settings.General.RememberWindowPlacement)
            {
                if (Program.Settings.General.WindowTop == 0 && Program.Settings.General.WindowLeft == 0)
                {
                    StartPosition = FormStartPosition.CenterScreen;
                }
                else
                {
                    StartPosition = FormStartPosition.Manual;
                    Top = Program.Settings.General.WindowTop;
                    Left = Program.Settings.General.WindowLeft;
                }

                Height = Program.Settings.General.WindowHeight;
                Width = Program.Settings.General.WindowWidth;
                WindowState = Program.Settings.General.FormWindowState;
            }

            ToggleCommentsPane();

            if (args != null && args.Length > 0)
            {
                int argStart = 0;
                switch (args[0].ToLower())
                {
                    case "/verify":
                        _initialVerify = true;
                        argStart++;
                        break;

                    case "/create":
                        _initialCreate = true;
                        argStart += 2;
                        break;

                    default:
                        _initialVerify = true;
                        break;
                }

                List<string> files = new List<string>();
                for (int i = argStart; i < args.Length; i++)
                {
                    files.Add(args[i]);
                }

                if (_initialVerify)
                {
                    EngageDropTimer(files);
                }
                else if (_initialCreate)
                {
                    switch (args[1].ToLower())
                    {
                        case "sfv":
                            _initialCreateChecksumType = ChecksumType.SFV;
                            break;

                        case "md5":
                            _initialCreateChecksumType = ChecksumType.MD5;
                            break;

                        case "sha1":
                            _initialCreateChecksumType = ChecksumType.SHA1;
                            break;

                        default:
                            throw new Exception(string.Format("{0} not implemented", args[1]));
                    }

                    EngageCreateTimer(files);
                }
            }

            _timer = new Timer();
            _timer.Interval = 1;
            _timer.Tick += _timer_Tick;
            _timer.Enabled = true;

            Load += MainForm_Load;
        }

        private void MainForm_Load(object sender, EventArgs e)
        {
            SendMessage(lvwFiles.Handle, LVM_SETTEXTBKCOLOR, IntPtr.Zero, unchecked((IntPtr)(int)0xFFFFFF));
        }

        private void notifyIcon1_BalloonTipClicked(object sender, EventArgs e)
        {
            UnhideFromSystray();
        }

        private readonly List<string> _newSets = new List<string>();

        private void _fsw_Created(object sender, FileSystemEventArgs e)
        {
            try
            {
                List<string> newSets = new List<string>();

                string path = e.FullPath;
                if (File.Exists(path))
                {
                    Thread.Sleep(500);

                    string[] files = File.ReadAllLines(path);
                    File.Delete(path);

                    foreach (string file in files)
                    {
                        newSets.Add(file);
                    }
                }

                UnhideFromSystray();
                Application.DoEvents();

                if (!_workingOnList)
                {
                    QueueNewSets(newSets);
                }
                else
                {
                    lock (_newSets)
                    {
                        foreach (string set in newSets)
                            _newSets.Add(set);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, Language.General.Error, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void QueueNewSets(List<string> newSets)
        {
            if (InvokeRequired)
            {
                Invoke(new Action<List<string>>(QueueNewSets), newSets);
            }
            else
            {
                EngageDropTimer(newSets);
            }
        }

        private void LoadNewSets()
        {
            if (InvokeRequired)
            {
                Invoke(new MethodInvoker(LoadNewSets));
            }
            else
            {
                List<string> newSets;
                lock (_newSets)
                {
                    if (_newSets.Count == 0)
                        return;

                    Activate();

                    newSets = new List<string>(_newSets);
                    _newSets.Clear();
                }

                ListViewBeginUpdate();
                try
                {
                    foreach (string set in newSets)
                        LoadAndVerifyFile(set, Program.Settings.Check.AutoVerify, true);
                }
                finally
                {
                    ListViewEndUpdate();
                }
            }
        }

        private void _timer_Tick(object sender, EventArgs e)
        {
            _timer.Enabled = false;

            SetAlwaysOnTop();

            if (Program.Settings.General.CheckForUpdates)
            {
                if (Program.Settings.General.LastUpdateCheck + TimeSpan.FromDays(Program.Settings.General.UpdateCheckFrequency) < DateTime.Now)
                {
                    try
                    {
                        CheckForUpdates(false);
                    }
                    catch (Exception ex)
                    {
                        // error checking for updates
                        Trace.WriteLine(ex);
                    }
                }
            }
        }

        private static void CheckForUpdates(bool verbose)
        {
            if (verbose)
                Cursor.Current = Cursors.WaitCursor;

            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            int major = version.Major;
            int minor = version.Minor;
            int build = version.Build;

            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072; // Tls12
            WebClient client = new WebClient();
            client.Headers.Add("user-agent", string.Format("ilSFV v{0}.{1}.{2}", major, minor, build));
            string json = client.DownloadString("https://api.github.com/repos/judwhite/ilSFV/releases");
            JArray releases = JsonConvert.DeserializeObject<JArray>(json);
            JToken lastRelease = releases.Where(r => !r.Value<bool>("draft") && !r.Value<bool>("prerelease"))
                .OrderByDescending(o => o.Value<string>("published_at")).FirstOrDefault();

            Program.Settings.General.LastUpdateCheck = DateTime.Now;

            if (lastRelease == null)
                return;

            // "name": "v1.10.0",
            string[] strparts = lastRelease.Value<string>("name").Split(new[] { '.', 'v' }, StringSplitOptions.RemoveEmptyEntries);
            int[] parts = strparts.Select(p => int.TryParse(p, out _) ? int.Parse(p) : -1).ToArray();

            if (verbose)
                Cursor.Current = Cursors.Default;

            if ((parts.Length >= 1 && major < parts[0]) ||
                (parts.Length >= 2 && major == parts[0] && minor < parts[1]) ||
                (parts.Length >= 3 && major == parts[0] && minor == parts[1] && build < parts[2]))
            {
                DialogResult res = MessageBox.Show(
                    string.Format(Language.MainForm.UpdateAvailable_Message, parts[0], parts[1], parts[2]),
                    Language.MainForm.UpdateAvailable_Title,
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question
                );

                if (res == DialogResult.Yes)
                {
                    // "html_url": "https://github.com/judwhite/ilSFV/releases/tag/v1.10.0",
                    Process.Start(lastRelease.Value<string>("html_url"));
                }
            }
            else
            {
                if (verbose)
                {
                    MessageBox.Show(Language.MainForm.NoUpdateAvailable_Message, Language.MainForm.NoUpdateAvailable_Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }

        /// <summary>
        /// Notifies the user that the application requests attention
        /// by flashing the taskbar if the form is not the current window.
        /// </summary>
        /// <param name="myForm">The form in question.</param>
        public static void FlashWindow(Form myForm)
        {
            // if the current foreground window isn't this window, flash this window in task bar once every 1 second
            // ReSharper disable EmptyGeneralCatchClause
            try
            {
                if (GetForegroundWindow() != myForm.Handle)
                    FlashWindow(myForm.Handle, true);
            }
            catch
            {
            }
            // ReSharper restore EmptyGeneralCatchClause
        }

        private long _totalSizeOfSets;
        private void GetWorkset(string fileName, string directoryName, ChecksumType setType, List<string> filesAndFolders, out int overwriteCount)
        {
            SetStatusText(Language.MainForm.Status_GettingFileList);
            Application.DoEvents();

            IDictionary<string, List<string>> files;

            if (filesAndFolders == null)
            {
                if (Program.Settings.General.Recursive)
                {
                    files = GetFilesAllDirectories(directoryName);
                }
                else
                {
                    files = new Dictionary<string, List<string>>();
                    files.Add(directoryName, Directory.GetFiles(directoryName, "*.*", SearchOption.TopDirectoryOnly).ToList());
                }
            }
            else
            {
                files = new Dictionary<string, List<string>>();
                foreach (string item in filesAndFolders)
                {
                    if (Directory.Exists(item))
                    {
                        if (Program.Settings.General.Recursive)
                        {
                            foreach (var kvp in GetFilesAllDirectories(item))
                            {
                                files.Add(kvp.Key, kvp.Value);
                            }
                        }
                        else
                        {
                            files.Add(item, Directory.GetFiles(item, "*.*", SearchOption.TopDirectoryOnly).ToList());
                        }
                    }
                    else
                    {
                        List<string> topFiles;
                        if (!files.TryGetValue(directoryName, out topFiles))
                        {
                            topFiles = new List<string>();
                            files.Add(directoryName, topFiles);
                        }
                        topFiles.Add(item);
                    }
                }
            }

            if (Program.Settings.Create.SortFiles)
            {
                SetStatusText(Language.MainForm.Status_PreSorting);
                Application.DoEvents();

                files = new SortedDictionary<string, List<string>>(files, StringComparer.InvariantCultureIgnoreCase);
                foreach (KeyValuePair<string, List<string>> kvp in new Dictionary<string, List<string>>(files))
                {
                    files[kvp.Key] = kvp.Value.OrderBy(p => p).ToList();
                }
            }

            SetStatusText(Language.MainForm.Status_GettingFileInfo);
            Application.DoEvents();

            List<string> excludeExt = new List<string>();
            if (!string.IsNullOrEmpty(Program.Settings.Create.ExcludeFilesOfType))
            {
                string[] exts = Program.Settings.Create.ExcludeFilesOfType.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (string ext in exts)
                {
                    string extMod = ext.ToLower();
                    if (extMod.StartsWith("*"))
                        extMod = extMod.Substring(1, extMod.Length - 1);
                    if (extMod.StartsWith("."))
                    {
                        if (!excludeExt.Contains(extMod))
                            excludeExt.Add(extMod);
                    }
                }
            }

            _sets.Clear();

            ChecksumSet set = new ChecksumSet(fileName, directoryName, setType);
            string checksumExt = Path.GetExtension(fileName);

            if (!Program.Settings.Create.CreateForEachSubDir)
                _sets.Add(set);

            int trimLength = directoryName.Length;
            if (!directoryName.EndsWith("\\"))
                trimLength++;

            int filesProcessed = 0;
            int lastPercent = 0;
            int totalFiles = 0;

            foreach (KeyValuePair<string, List<string>> kvp in files)
            {
                totalFiles += kvp.Value.Count;
            }

            foreach (KeyValuePair<string, List<string>> kvp in files)
            {
                if (Program.Settings.Create.CreateForEachSubDir)
                {
                    string tmpFileName;
                    if (Program.Settings.Create.PromptForFileName)
                    {
                        tmpFileName = Path.Combine(kvp.Key, Path.GetFileName(fileName));
                    }
                    else
                    {
                        tmpFileName = Path.GetFileName(kvp.Key) + checksumExt;
                        tmpFileName = Path.Combine(kvp.Key, tmpFileName);
                    }
                    set = new ChecksumSet(tmpFileName, kvp.Key, setType);
                    _sets.Add(set);

                    trimLength = kvp.Key.Length;
                    if (!kvp.Key.EndsWith("\\"))
                        trimLength++;
                }

                long directoryTotalSize = 0;
                foreach (string file in kvp.Value)
                {
                    filesProcessed++;
                    int percent = (filesProcessed * 100 / totalFiles);

                    if (percent / 5 > lastPercent / 5)
                    {
                        SetStatusText(string.Format(Language.MainForm.Status_GettingFileInfoPercentage, (percent / 5) * 5));
                        Application.DoEvents();

                        lastPercent = percent;
                    }

                    bool ok = true;

                    foreach (string ext in excludeExt)
                    {
                        if (string.Compare(Path.GetExtension(file), ext, true) == 0)
                        {
                            ok = false;
                            break;
                        }
                    }

                    if (ok)
                    {
                        FileInfo fileInfo = TryGetNewFileInfo(file);
                        if ((fileInfo.Attributes & FileAttributes.Hidden) == FileAttributes.Hidden)
                            continue;

                        ChecksumFile checksumFile = new ChecksumFile(set);
                        checksumFile.FileInfo = fileInfo;
                        checksumFile.State = ChecksumFileState.NotProcessed;
                        checksumFile.FileName = file.Substring(trimLength, file.Length - trimLength);

                        set.Files.Add(checksumFile);

                        directoryTotalSize += fileInfo.Length;
                    }
                }

                set.TotalSize += directoryTotalSize;
            }

            overwriteCount = 0;
            foreach (ChecksumSet setx in _sets)
            {
                if (File.Exists(setx.VerificationFileName))
                    overwriteCount++;
            }
        }

        private static FileInfo TryGetNewFileInfo(string file)
        {
            FileInfo fileInfo;
            try
            {
                fileInfo = new FileInfo(file);
            }
            catch (Exception ex)
            {
                throw new Exception(string.Format("'{0}': {1}", file, ex.Message), ex);
            }

            return fileInfo;
        }

        private Dictionary<string, List<string>> GetFilesAllDirectories(string directoryName)
        {
            Dictionary<string, List<string>> dict = new Dictionary<string, List<string>>();
            GetFilesAllDirectories(directoryName, dict);
            return dict;
        }

        private void GetFilesAllDirectories(string directoryName, IDictionary<string, List<string>> dictionary)
        {
            SetStatusText(string.Format(Language.MainForm.Status_GettingFileListForDirectory, directoryName));
            Application.DoEvents();

            // Files
            try
            {
                string[] files = Directory.GetFiles(directoryName, "*.*", SearchOption.TopDirectoryOnly);

                if (files.Length != 0)
                    dictionary.Add(directoryName, files.ToList());
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex);
            }

            // Directories
            try
            {
                string[] directories = Directory.GetDirectories(directoryName, "*.*", SearchOption.TopDirectoryOnly);
                foreach (string directory in directories)
                {
                    DirectoryInfo di = new DirectoryInfo(directory);
                    if ((di.Attributes & FileAttributes.Hidden) == FileAttributes.Hidden) // skip hidden directories
                        continue;
                    GetFilesAllDirectories(directory, dictionary);
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex);
            }
        }

        private void miAbout_Click(object sender, EventArgs e)
        {
            ShowPreferences(true);
        }

        private void miPreferences_Click(object sender, EventArgs e)
        {
            ShowPreferences(false);
        }

        private void ShowPreferences(bool showAbout)
        {
            Cursor.Current = Cursors.WaitCursor;
            using (PreferencesForm form = new PreferencesForm(showAbout))
            {
                Cursor.Current = Cursors.Default;
                form.ShowDialog();
            }

            Language.Load(Program.Settings.General.Language);

            if (!Program.Settings.General.IsRecentFilesSaved)
            {
                using (SqlCeCommand cmd = new SqlCeCommand("delete from RecentFile", Program.GetOpenSettingsConnection()))
                {
                    cmd.ExecuteNonQuery();
                }
            }

            SetAlwaysOnTop();
        }

        private void SetAlwaysOnTop()
        {
            if (Program.Settings.General.AlwaysOnTop)
                FormHelper.MakeTopMost(this);
            else
                FormHelper.MakeNormal(this);
        }

        private void MainForm_Resize(object sender, EventArgs e)
        {
            SaveFormSizeAndPosition();

            ResizeStatusBar();

            progressBar1.Width = chkHideGood.Left - 16;
        }

        private void SaveFormSizeAndPosition()
        {
            if (IsHandleCreated)
            {
                if (WindowState != FormWindowState.Minimized)
                {
                    if (WindowState != FormWindowState.Maximized)
                    {
                        Program.Settings.General.WindowTop = Top;
                        Program.Settings.General.WindowLeft = Left;
                        Program.Settings.General.WindowHeight = Height;
                        Program.Settings.General.WindowWidth = Width;
                    }
                    Program.Settings.General.FormWindowState = WindowState;
                }
            }
        }

        private void ResizeStatusBar()
        {
            int statusWidth = statusStrip1.Width / 2 + 5;
            lblStatus.Width = statusWidth;

            int partsWidth = (statusStrip1.Width - statusWidth) / 5 - 1;
            lblSets.Width = partsWidth;
            lblParts.Width = partsWidth;
            lblGood.Width = partsWidth;
            lblBad.Width = partsWidth;
            lblMissing.Width = partsWidth;
        }

        private void SetStatusText(string text)
        {
            lblStatus.Text = text;

            if (text.Length >= 64)
                text = text.Substring(0, 60) + "...";
            notifyIcon1.Text = text;
        }

        private static List<string> GetChecksumFiles(bool multiSelect)
        {
            string[] fileNames;

            Cursor.Current = Cursors.WaitCursor;
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Filter = "*.md5;*.sfv;*.sha1|*.md5;*.sfv;*.sha1";
                ofd.Multiselect = multiSelect;
                Cursor.Current = Cursors.Default;
                DialogResult res = ofd.ShowDialog();
                if (res != DialogResult.OK)
                    return null;
                fileNames = ofd.FileNames;
            }

            return fileNames.ToList();
        }

        private void miOpen_Click(object sender, EventArgs e)
        {
            List<string> fileNames = GetChecksumFiles(true);
            if (fileNames == null)
                return;

            EngageDropTimer(fileNames);
        }

        public bool LoadAndVerifyFile(string fileName, bool doVerify, bool getFileInfo)
        {
            if (Directory.Exists(fileName))
            {
                List<string> verifyFiles = new List<string>();
                Dictionary<string, List<string>> dict = GetFilesAllDirectories(fileName);
                foreach (List<string> dirFiles in dict.Values)
                {
                    foreach (string dirFile in dirFiles)
                    {
                        string dirFileExt = Path.GetExtension(dirFile).ToLower();
                        if (dirFileExt == ".md5" || dirFileExt == ".sfv" || dirFileExt == ".sha1")
                            verifyFiles.Add(dirFile);
                    }
                }

                ListViewBeginUpdate();
                try
                {
                    foreach (string verifyFile in verifyFiles)
                        LoadAndVerifyFile(verifyFile, doVerify, getFileInfo);
                }
                finally
                {
                    ListViewEndUpdate();
                }

                return true;
            }

            if (!File.Exists(fileName))
            {
                MessageBox.Show(string.Format(Language.MainForm.FileNotFound_Message, fileName), Language.MainForm.FileNotFound_Title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            string baseDirectory = Path.GetDirectoryName(fileName);

            string ext = Path.GetExtension(fileName).ToLower();
            ChecksumType setType;
            if (ext == ".md5")
                setType = ChecksumType.MD5;
            else if (ext == ".sfv")
                setType = ChecksumType.SFV;
            else if (ext == ".sha1")
                setType = ChecksumType.SHA1;
            else
                return false;

            ChecksumSet set = new ChecksumSet(fileName, baseDirectory, setType);

            SetStatusText(string.Format(Language.MainForm.Status_LoadingFile, set.VerificationFileName));
            Application.DoEvents();

            Program.Settings.AddRecentFile(fileName);

            ListViewBeginUpdate();
            try
            {
                if (!_workingOnList)
                {
                    lvwFiles.Items.Clear();
                    lvwFiles.Groups.Clear();
                    Application.DoEvents();
                }

                string[] lines = File.ReadAllLines(fileName, Encoding.GetEncoding(CODE_PAGE));
                List<string> quicksfvLines = new List<string>();

                ListViewGroup group = new ListViewGroup(lvwFiles.Groups.Count.ToString(), Path.GetFileName(fileName));
                lvwFiles.Groups.Add(group);

                StringBuilder comment = new StringBuilder();
                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i];
                    if (line == null)
                        continue;

                    line = line.Trim();
                    if (string.IsNullOrEmpty(line))
                        continue;

                    if (line.StartsWith(";") ||
                        (line.StartsWith("#") && (set.Type == ChecksumType.MD5 || set.Type == ChecksumType.SHA1)))
                    {
                        comment.AppendLine(line.Substring(1, line.Length - 1));

                        if (line.StartsWith(";Q"))
                            quicksfvLines.Add(line);
                    }
                    else
                    {
                        ChecksumFile file = new ChecksumFile(set);

                        if (set.Type == ChecksumType.MD5)
                        {
                            string chkMD5;
                            string chkFileName;

                            if (line.StartsWith("MD5 ("))
                            {
                                int idx = line.LastIndexOf(' ');
                                if (idx == -1)
                                    throw new InvalidChecksumFileException(fileName, set.Type, lines, i, CODE_PAGE);
                                chkFileName = line.Substring(5, idx - 5 - 3);
                                chkMD5 = line.Substring(idx + 1, line.Length - idx - 1);
                                if (chkMD5.Length != 32)
                                    throw new InvalidChecksumFileException(fileName, set.Type, lines, i, CODE_PAGE);
                            }
                            else
                            {
                                int idx = line.IndexOf(' ');
                                if (idx == -1)
                                    throw new InvalidChecksumFileException(fileName, set.Type, lines, i, CODE_PAGE);

                                if (idx == 32)
                                {
                                    chkMD5 = line.Substring(0, idx);
                                    chkFileName = line.Substring(idx + 1, line.Length - idx - 1);
                                }
                                else
                                {
                                    idx = line.LastIndexOf(' ');
                                    if (idx == -1)
                                        throw new InvalidChecksumFileException(fileName, set.Type, lines, i, CODE_PAGE);
                                    chkFileName = line.Substring(0, idx);
                                    chkMD5 = line.Substring(idx + 1, line.Length - idx - 1);
                                    if (chkMD5.Length != 32)
                                        throw new InvalidChecksumFileException(fileName, set.Type, lines, i, CODE_PAGE);
                                }
                            }

                            if (chkFileName.StartsWith("*")) // md5sum
                                chkFileName = chkFileName.Substring(1);

                            file.FileName = chkFileName;
                            file.OriginalChecksum = chkMD5;
                        }
                        else if (set.Type == ChecksumType.SHA1)
                        {
                            string chkSHA1;
                            string chkFileName;

                            if (line.StartsWith("SHA1 ("))
                            {
                                int idx = line.LastIndexOf(' ');
                                if (idx == -1)
                                    throw new InvalidChecksumFileException(fileName, set.Type, lines, i, CODE_PAGE);
                                chkFileName = line.Substring(6, idx - 6 - 3);
                                chkSHA1 = line.Substring(idx + 1, line.Length - idx - 1);
                                if (chkSHA1.Length != 40)
                                    throw new InvalidChecksumFileException(fileName, set.Type, lines, i, CODE_PAGE);
                            }
                            else
                            {
                                int idx = line.IndexOf(' ');
                                if (idx == -1)
                                    throw new InvalidChecksumFileException(fileName, set.Type, lines, i, CODE_PAGE);

                                if (idx == 40)
                                {
                                    chkSHA1 = line.Substring(0, idx);
                                    chkFileName = line.Substring(idx + 1, line.Length - idx - 1);
                                }
                                else
                                {
                                    idx = line.LastIndexOf(' ');
                                    if (idx == -1)
                                        throw new InvalidChecksumFileException(fileName, set.Type, lines, i, CODE_PAGE);
                                    chkFileName = line.Substring(0, idx);
                                    chkSHA1 = line.Substring(idx + 1, line.Length - idx - 1);
                                    if (chkSHA1.Length != 40)
                                        throw new InvalidChecksumFileException(fileName, set.Type, lines, i, CODE_PAGE);
                                }
                            }

                            if (chkFileName.StartsWith("*")) // md5sum
                                chkFileName = chkFileName.Substring(1);

                            file.FileName = chkFileName;
                            file.OriginalChecksum = chkSHA1;
                        }
                        else if (set.Type == ChecksumType.SFV)
                        {
                            int idx = line.LastIndexOf(' ');
                            if (idx == -1)
                                throw new InvalidChecksumFileException(fileName, set.Type, lines, i, CODE_PAGE);
                            string chkSFV = line.Substring(idx + 1, line.Length - idx - 1);
                            string chkFileName = line.Substring(0, idx);

                            if (chkSFV.StartsWith("$")) // remove leading $
                                chkSFV = chkSFV.Substring(1);
                            if (chkSFV.StartsWith("0x") || chkSFV.StartsWith("0X")) // remove leading 0x
                                chkSFV = chkSFV.Substring(2);
                            if (chkSFV.Length < 8) // cksfv v1.1 does not write the leading zeros
                                chkSFV = chkSFV.PadLeft(8, '0');

                            if (chkSFV.Length != 8)
                                throw new InvalidChecksumFileException(fileName, set.Type, lines, i, CODE_PAGE);

                            file.FileName = chkFileName;
                            file.OriginalChecksum = chkSFV;
                        }
                        else
                        {
                            throw new Exception(string.Format("{0} not implemented", set.Type));
                        }

                        file.FileName = file.FileName.Replace('/', '\\');

                        // NOTE: Looks like hkSFV ignores this setting for checking
                        //if (!Program.Settings.General.Recursive && file.FileName.Contains('\\'))
                        //	continue;

                        set.Files.Add(file);

                        ListViewItem item = new ListViewItem(new[] { file.FileName, file.Guid });
                        item.Tag = file;
                        item.StateImageIndex = 0;
                        item.Group = group;
                        lvwFiles.Items.Add(item);
                    }
                }

                set.Comments = comment.ToString();
                AnalyzeQuicksfvDatabase(set, quicksfvLines);

                if (lvwFiles.Items.Count != 0)
                    lvwFiles.AutoResizeColumn(0, ColumnHeaderAutoResizeStyle.ColumnContent);
            }
            finally
            {
                ListViewEndUpdate();
            }

            if (!_workingOnList)
            {
                _totalSizeOfSets = 0;
                _files_parts = 0;
                _sets.Clear();
            }

            if (getFileInfo)
            {
                int lastPercent = 0;
                set.TotalSize = 0;
                for (int i = 0; i < set.Files.Count; i++)
                {
                    int percent = (i * 100 / set.Files.Count);

                    if (percent / 5 > lastPercent / 5)
                    {
                        SetStatusText(string.Format(Language.MainForm.Status_LoadingFilePercentage, set.VerificationFileName, (percent / 5) * 5));
                        Application.DoEvents();

                        lastPercent = percent;
                    }

                    ChecksumFile file = set.Files[i];

                    string fullFileName = Path.Combine(set.Directory, file.FileName);

                    if (File.Exists(fullFileName))
                    {
                        FileInfo fileInfo = TryGetNewFileInfo(fullFileName);
                        file.FileInfo = fileInfo;
                        set.TotalSize += fileInfo.Length;
                    }
                }
            }

            _totalSizeOfSets += set.TotalSize;
            _files_parts += set.Files.Count;

            _sets.Add(set);

            if (!_workingOnList && doVerify)
                Verify();

            return true;
        }

        private void AnalyzeQuicksfvDatabase(ChecksumSet set, List<string> quicksfvLines)
        {
            if (quicksfvLines.Count == 0)
            {
                set.QuickSfvAnalysis = null;
                return;
            }

            StringBuilder analysis = new StringBuilder();
            Regex oldSignature = new Regex("^[0-9A-F]{15}$", RegexOptions.IgnoreCase);
            Regex newSignature = new Regex("^[0-9]{10}$", RegexOptions.IgnoreCase);
            bool timeHandled = false;

            foreach (string line in quicksfvLines)
            {
                string content = line.Substring(4); // skip ;Q3-

                if (newSignature.IsMatch(content))
                {
                    analysis.AppendLine(string.Format("Installation signature Q3: {0} (random 10-digit number)", content));
                }
                else if (oldSignature.IsMatch(content))
                {
                    int startLow = content.Length - 8;
                    FILETIME ft = new FILETIME()
                    {
                        dwLowDateTime = int.Parse(content.Substring(startLow), NumberStyles.HexNumber),
                        dwHighDateTime = int.Parse(content.Substring(0, startLow), NumberStyles.HexNumber)
                    };
                    DateTime installDate = ConvertToDateTime(ft);

                    analysis.AppendLine(string.Format("Installation signature: {0} (QuickSFV 1 and 2)", content));
                    analysis.AppendLine(string.Format("Installation date: {0:O} (from signature)", installDate));
                }
                else
                {
                    byte[] bytes = Convert.FromBase64String(content);

                    if (bytes.Length == 8 && !timeHandled)
                    {
                        int startHigh = bytes.Length - 4;
                        FILETIME ft = new FILETIME()
                        {
                            dwLowDateTime = BitConverter.ToInt32(bytes.Take(startHigh).ToArray(), 0),
                            dwHighDateTime = BitConverter.ToInt32(bytes, startHigh)
                        };
                        DateTime checkDate = ConvertToDateTime(ft);

                        analysis.AppendLine(string.Format("Verification date last verified: {0:O}", checkDate));
                        timeHandled = !timeHandled;
                    }
                    else
                    {
                        // bit array: 1 -> it succeeded, 0 -> it failed
                        analysis.AppendLine("File status last verification:");

                        int sfvFileCounter = 0;
                        foreach (byte status in bytes)
                        {
                            for (int i = 7; i >= 0; i--)
                            {
                                string fileName = set.Files.ElementAtOrDefault(sfvFileCounter)?.FileName;

                                if ((status & (int)Math.Pow(2, i)) == 0)
                                    analysis.Append("NOT ");

                                analysis.Append("OK: ").AppendLine(fileName);

                                sfvFileCounter++;
                                if (sfvFileCounter + 1 > set.Files.Count)
                                    break;
                            }
                        }

                        timeHandled = !timeHandled;
                    }
                }
            }

            set.QuickSfvAnalysis = analysis.ToString();

            DateTime ConvertToDateTime(FILETIME ft)
            {
                ulong high = (ulong)ft.dwHighDateTime;
                uint low = (uint)ft.dwLowDateTime;
                long fileTime = (long)((high << 32) + low);
                DateTime checkDate;
                try
                {
                    checkDate = DateTime.FromFileTimeUtc(fileTime);
                }
                catch
                {
                    checkDate = DateTime.FromFileTimeUtc(0xFFFFFFFF);
                }

                return checkDate;
            }
        }

        private void btnRightPane_Click(object sender, EventArgs e)
        {
            Program.Settings.General.ShowCommentsPane = !Program.Settings.General.ShowCommentsPane;
            ToggleCommentsPane();
        }

        private void miCommentResultPane_Click(object sender, EventArgs e)
        {
            Program.Settings.General.ShowCommentsPane = !Program.Settings.General.ShowCommentsPane;
            ToggleCommentsPane();
        }

        private void ToggleCommentsPane()
        {
            bool show = Program.Settings.General.ShowCommentsPane;

            splitContainer1.Panel2Collapsed = !show;

            // Buttons and Menu Items
            btnRightPane.Text = show ? "<<" : ">>";
            miCommentResultPane.Checked = show;

            progressBar1.Width = chkHideGood.Left - 16;
        }

        private void miHideGood_Click(object sender, EventArgs e)
        {
            chkHideGood.Checked = !miHideGood.Checked;
        }

        private void chkHideGood_CheckedChanged(object sender, EventArgs e)
        {
            miHideGood.Checked = chkHideGood.Checked;
            Program.Settings.General.HideGoodFiles = miHideGood.Checked;

            if (_workingOnList)
                _queueHideGood = true;
            else
                ApplyHideGood();
        }

        private void ApplyHideGood()
        {
            _queueHideGood = false;

            if (_sets.Count == 0)
                return;

            ListViewBeginUpdate();
            try
            {
                lvwFiles.Items.Clear();
                lvwFiles.Groups.Clear();

                foreach (ChecksumSet set in _sets)
                {
                    ListViewGroup group = new ListViewGroup(lvwFiles.Groups.Count.ToString(), Path.GetFileName(set.VerificationFileName));
                    lvwFiles.Groups.Add(group);

                    foreach (ChecksumFile file in set.Files)
                    {
                        if (file.State == ChecksumFileState.OK && Program.Settings.General.HideGoodFiles)
                            continue;

                        ListViewItem item = new ListViewItem(new[] { file.FileName, file.Guid });
                        item.Tag = file;
                        item.StateImageIndex = (int)file.State;
                        item.Group = group;
                        lvwFiles.Items.Add(item);
                    }
                }
            }
            finally
            {
                ListViewEndUpdate();
            }

            lvwFiles.Focus();
        }

        private void btnGo_Click(object sender, EventArgs e)
        {
            if (!_workingOnList)
            {
                foreach (ChecksumSet set in _sets)
                {
                    foreach (ChecksumFile file in set.Files)
                        file.State = ChecksumFileState.NotProcessed;
                }

                ApplyHideGood();

                Verify();
            }
            else
            {
                _queueStop = true;
            }
        }

        private int _files_parts;
        private int _files_ok;
        private int _files_missing;
        private int _files_bad;
        private int _set_index;

        private void Verify()
        {
            if (_sets.Count == 0)
                return;

            long bytesProcessed = 0;
            _workingOnList = true;

            try
            {
                SetStatusText(Language.MainForm.Status_Working);
                btnPause.Enabled = true;
                btnHide.Enabled = true;

                ToggleMenuItemsEnabled(false, false);

                btnGo.Text = Language.MainForm.StopButton;
                _queueStop = false;
                _pause = false;
                _stopwatch.Restart();

                progressBar1.Value = 0;
                progressBar2.Value = 0;

                _files_ok = 0;
                _files_bad = 0;
                _files_missing = 0;

                for (_set_index = 0; _set_index < _sets.Count; _set_index++)
                {
                    if (_queueStop)
                        break;

                    UpdateStatusBar();

                    ChecksumSet set = _sets[_set_index];
                    txtComments.Text = set.Comments;
                    txtQuickSFV.Text = set.QuickSfvAnalysis;
                    if (string.IsNullOrEmpty(set.QuickSfvAnalysis))
                        tpQuickSFV.Parent = null;
                    else
                        tpQuickSFV.Parent = tabControl1;

                    lvwFiles.Focus();
                    Application.DoEvents();

                    List<ChecksumFile> cache = Cache.GetCache(set.Type, set.Directory);

                    for (int i = 0; i < set.Files.Count; i++)
                    {
                        if (_queueHideGood)
                            ApplyHideGood();

                        if (_pause)
                        {
                            while (_pause && !_queueStop)
                            {
                                if (_queueHideGood)
                                    ApplyHideGood();

                                Thread.Sleep(50);
                                Application.DoEvents();
                            }

                            if (_pause)
                                Unpause();

                            int pauseTotalPercent = _totalSizeOfSets == 0 ? 100 : (int)((bytesProcessed * 100) / _totalSizeOfSets);
                            SetStatusText(string.Format(Language.MainForm.Status_WorkingPercentage, pauseTotalPercent));
                            Application.DoEvents();
                        }

                        if (_queueStop)
                            break;

                        LoadNewSets();

                        ChecksumFile file = set.Files[i];
                        ListViewItem listItem = lvwFiles.FindItemWithText(file.Guid);

                        progressBar1.Value = 0;
                        listItem.Selected = true;
                        //lvwFiles.FocusedItem = listItem;
                        if (Program.Settings.General.AutoScrollFileList)
                            listItem.EnsureVisible();
                        //Application.DoEvents();

                        bool checkCacheThisFile = Program.Settings.General.UseCachedResults;

                        // file checks for each rerun
                        string fullFileName = Path.Combine(set.Directory, file.FileName);
                        if (File.Exists(fullFileName))
                        {
                            if (file.FileInfo == null)
                            {
                                // the file isn't missing anymore
                                file.FileInfo = TryGetNewFileInfo(fullFileName);
                                checkCacheThisFile = false;
                            }
                        }
                        else
                        {
                            if (file.FileInfo != null)
                                file.FileInfo = null;
                        }

                        // check for .bad if missing
                        if (file.FileInfo == null)
                        {
                            string badFileName = fullFileName + ".bad";
                            if (File.Exists(badFileName))
                            {
                                File.Move(badFileName, fullFileName);
                                file.FileInfo = TryGetNewFileInfo(fullFileName);
                                checkCacheThisFile = false;
                            }
                        }

                        if (file.FileInfo == null)
                        {
                            file.State = ChecksumFileState.Missing;
                            _files_missing++;

                            // Create .missing marker
                            if (Program.Settings.Check.CreateMissingMarkers)
                            {
                                string missingFileName = Path.Combine(set.Directory, file.FileName) + ".missing";
                                if (!File.Exists(missingFileName))
                                {
                                    File.WriteAllBytes(missingFileName, new byte[0]);
                                }
                            }
                        }
                        else
                        {
                            bytesProcessed += file.FileInfo.Length;

                            // Clean up .bad/.missing
                            if (Program.Settings.Check.CleanupBadMissing)
                            {
                                // .missing
                                string missingFileName = file.FileInfo.FullName + ".missing";
                                if (File.Exists(missingFileName))
                                {
                                    if (TryGetNewFileInfo(missingFileName).Length == 0)
                                        File.Delete(missingFileName);
                                }

                                // .bad
                                string badFileName = file.FileInfo.FullName + ".bad";
                                if (File.Exists(badFileName))
                                {
                                    if (TryGetNewFileInfo(badFileName).Length == 0)
                                        File.Delete(badFileName);
                                }
                            }

                            // Renaming
                            if (Program.Settings.Check.Renaming != CheckRenaming.None)
                            {
                                string[] realFiles = Directory.GetFiles(file.FileInfo.Directory.FullName, file.FileInfo.Name);
                                string realFileName = Path.GetFileName(realFiles.FirstOrDefault() ?? file.FileInfo.FullName);
                                string newFileName = null;

                                if (Program.Settings.Check.Renaming == CheckRenaming.Lowercase)
                                {
                                    if (realFileName != realFileName.ToLower())
                                    {
                                        newFileName = realFileName.ToLower();
                                    }
                                }
                                else if (Program.Settings.Check.Renaming == CheckRenaming.MatchSet)
                                {
                                    string sfvFileName = Path.GetFileName(Path.Combine(set.Directory, file.FileName));
                                    if (realFileName != sfvFileName)
                                    {
                                        newFileName = sfvFileName;
                                    }
                                }
                                else if (Program.Settings.Check.Renaming == CheckRenaming.PreserveCapitalizaton)
                                {
                                    string sfvFileName = Path.GetFileName(Path.Combine(set.Directory, file.FileName));
                                    bool realHasCapitals = realFileName != realFileName.ToLower();
                                    bool sfvHasCapitals = sfvFileName != sfvFileName.ToLower();
                                    if (!realHasCapitals && sfvHasCapitals)
                                    {
                                        newFileName = sfvFileName;
                                    }
                                }

                                if (!string.IsNullOrEmpty(newFileName))
                                {
                                    string fullNewFileName = Path.Combine(Path.GetDirectoryName(file.FileInfo.FullName), newFileName);

                                    Random r = new Random();
                                    string tempFileName;
                                    do
                                    {
                                        tempFileName = string.Format("{0}.{1}", fullNewFileName, r.Next(0, 9999));

                                    } while (File.Exists(tempFileName));

                                    File.Move(file.FileInfo.FullName, tempFileName);
                                    File.Move(tempFileName, fullNewFileName);
                                }
                            }

                            file.CurrentChecksum = null;

                            // Check cache
                            ChecksumFile foundItem = null;
                            if (checkCacheThisFile)
                            {
                                foreach (ChecksumFile cacheItem in cache)
                                {
                                    if (cacheItem.CacheLength == file.FileInfo.Length &&
                                        string.Compare(cacheItem.FileName, file.FileInfo.FullName, true) == 0)
                                    {
                                        TimeSpan delta = cacheItem.CacheLastWriteUtc - GetLastWriteTimeUtc(file.FileInfo);
                                        if (delta < TimeSpan.FromSeconds(0.01) && delta > TimeSpan.FromSeconds(-0.01))
                                        {
                                            file.CurrentChecksum = cacheItem.OriginalChecksum;
                                            foundItem = cacheItem;
                                            break;
                                        }
                                    }
                                }
                            }

                            bool cachedBefore = foundItem != null;
                            if (cachedBefore)
                            {
                                cache.Remove(foundItem);

                                // Early check. If cached item fails check, recheck w/o using cache
                                if (string.Compare(file.CurrentChecksum, file.OriginalChecksum, true) != 0)
                                {
                                    file.CurrentChecksum = null;
                                    foundItem = null;
                                }
                                else
                                {
                                    // use cached result
                                    file.State = ChecksumFileState.OK;
                                    _files_ok++;
                                }
                            }

                            // Calculate crc32/md5
                            if (string.IsNullOrEmpty(file.CurrentChecksum))
                            {
                                IProgress<long> progress = new Progress<long>(bytesRead => UpdateFileProgressBar(file.FileInfo.Length, bytesRead));

                                if (set.Type == ChecksumType.MD5)
                                {
                                    file.CurrentChecksum = GetChecksumWithProgress(MD5WithProgress, file.FileInfo, progress);
                                    if (string.IsNullOrEmpty(file.CurrentChecksum))
                                        continue;

                                    CheckForChecksumMatch(file);

                                    if (!cachedBefore && file.State == ChecksumFileState.OK)
                                        Cache.UpdateMD5Cache(file.FileInfo, file.CurrentChecksum);
                                }
                                else if (set.Type == ChecksumType.SFV)
                                {
                                    file.CurrentChecksum = GetChecksumWithProgress(CRC32WithProgress, file.FileInfo, progress);
                                    if (string.IsNullOrEmpty(file.CurrentChecksum))
                                        continue;

                                    CheckForChecksumMatch(file);

                                    if (!cachedBefore && file.State == ChecksumFileState.OK)
                                        Cache.UpdateSFVCache(file.FileInfo, file.CurrentChecksum);
                                }
                                else if (set.Type == ChecksumType.SHA1)
                                {
                                    file.CurrentChecksum = GetChecksumWithProgress(SHA1WithProgress, file.FileInfo, progress);
                                    if (string.IsNullOrEmpty(file.CurrentChecksum))
                                        continue;

                                    CheckForChecksumMatch(file);

                                    if (!cachedBefore && file.State == ChecksumFileState.OK)
                                        Cache.UpdateSHA1Cache(file.FileInfo, file.CurrentChecksum);
                                }
                                else
                                {
                                    throw new Exception(string.Format("{0} not implemented", set.Type));
                                }
                            }
                        }

                        // update status bar, listview, progressbar
                        UpdateStatusBar();

                        listItem.StateImageIndex = (int)file.State;

                        UpdateProgressBarsAndText(bytesProcessed);

                        if (Program.Settings.General.HideGoodFiles && file.State == ChecksumFileState.OK)
                            lvwFiles.Items.Remove(listItem);

                        Application.DoEvents();
                    }

                    progressBar1.Value = 100;
                    progressBar2.Value = 100;

                    if (Program.Settings.Check.AutoFindRenames && _files_missing != 0)
                    {
                        int tmp;
                        FindRenamedFiles(set, out tmp);
                        UpdateProgressBarsAndText(bytesProcessed);
                    }

                    if (_queueHideGood)
                        ApplyHideGood();

                    LoadNewSets();
                }

                _stopwatch.Stop(); 
                SetStatusText(Language.MainForm.Status_UpdatingCache);
                Application.DoEvents();
                TimeSpan timeSpent = _stopwatch.Elapsed;
                Program.Settings.Statistics.AddStats(_files_ok + _files_bad + _files_missing, _set_index, bytesProcessed / 1024 / 1024, _files_ok, timeSpent);
                Cache.Clean();

                if (Program.Settings.Check.AutoCloseWhenDoneChecking)
                {
                    if (_files_parts == _files_ok || !Program.Settings.Check.AutoCloseWhenDoneCheckingOnlyIfAllOK)
                    {
                        Close();
                    }
                }

                if (Program.Settings.General.FlashWindowWhenDone)
                    FlashWindow(this);
            }
            finally
            {
                TimeSpan totalTime = _stopwatch.Elapsed;
                decimal totalMB = bytesProcessed / 1024.0m / 1024.0m;
                int percentGood = _files_parts == 0 ? 0 : (_files_ok * 100) / _files_parts;
                decimal mbPerSecond = totalTime.TotalSeconds > 0 ? totalMB / (decimal)totalTime.TotalSeconds : totalMB;
                string statusText;
                if (totalTime.TotalSeconds < 600)
                    statusText = string.Format(Language.MainForm.Status_FinishedUnder10Minutes, percentGood, totalMB, totalTime.TotalSeconds, mbPerSecond);
                else
                    statusText = string.Format(Language.MainForm.Status_Finished10MinutesOrMore, percentGood, totalMB, totalTime.Hours, totalTime.Minutes, totalTime.Seconds, mbPerSecond);

                ToolTipIcon icon = percentGood == 100 ? ToolTipIcon.Info : ToolTipIcon.Warning;
                notifyIcon1.ShowBalloonTip(3000, "ilSFV", string.Format(Language.MainForm.SystemTray_DoneVerifying, percentGood), icon);

                btnPause.Enabled = false;
                btnHide.Enabled = false;
                SetStatusText(statusText);
                PlayCompleteSound(_files_parts == _files_ok);

                ToggleMenuItemsEnabled(true, (_files_missing != 0));

                _workingOnList = false;
                btnGo.Text = Language.MainForm.GoButton;
                _queueStop = false;
            }
        }

        private void CheckForChecksumMatch(ChecksumFile file)
        {
            // test if it's ok/bad
            if (string.Compare(file.CurrentChecksum, file.OriginalChecksum, true) == 0)
            {
                file.State = ChecksumFileState.OK;
                _files_ok++;
            }
            else
            {
                file.State = ChecksumFileState.Bad;
                _files_bad++;

                // Rename to .bad
                string changedFileName = file.FileInfo.FullName;
                if (Program.Settings.Check.RenameBadFiles)
                {
                    string badFileName = changedFileName + ".bad";
                    if (!File.Exists(badFileName))
                    {
                        File.Move(changedFileName, badFileName);
                        changedFileName = badFileName;
                    }
                }

                // Delete failed files
                if (Program.Settings.Check.DeleteFailedFiles)
                    Program.SafeDelete(changedFileName);
            }
        }

        private void UpdateProgressBarsAndText(long bytesProcessed)
        {
            int filesLeft = _files_parts - _files_ok - _files_bad - _files_missing;
            decimal totalPercent = _totalSizeOfSets == 0 ? 100.0m : (bytesProcessed * 100.0m) / _totalSizeOfSets;
            if (totalPercent > 100)
                totalPercent = 100;
            progressBar2.Value = (int)totalPercent;

            TimeSpan elapsed = _stopwatch.Elapsed; 
            string strElapsed = string.Format("{0:0}:{1:00}:{2:00}", elapsed.Hours, elapsed.Minutes, elapsed.Seconds);
            TimeSpan eta = (double)totalPercent <= double.Epsilon ? TimeSpan.Zero : TimeSpan.FromSeconds(elapsed.TotalSeconds * 100.0 / (double)totalPercent - elapsed.TotalSeconds + 1.0);
            if (eta < TimeSpan.Zero)
                eta = TimeSpan.Zero;
            else
                eta += TimeSpan.FromSeconds(0.1 * filesLeft);
            string strETA = string.Format("{0:0}:{1:00}:{2:00}", eta.Hours, eta.Minutes, eta.Seconds);

            string statusText = string.Format(Language.MainForm.Status_ETA, (int)totalPercent, strETA, strElapsed);
            SetStatusText(statusText);
            Application.DoEvents();
        }

        private void ToggleMenuItemsEnabled(bool enabled, bool findRenamedEnabled)
        {
            miNewSFV.Enabled = enabled;
            miNewMD5.Enabled = enabled;
            miNewSHA1.Enabled = enabled;
            miPreferences.Enabled = enabled;
            miFindRenamedFiles.Enabled = findRenamedEnabled;
            miUseCachedResults.Enabled = enabled;
            miFindDuplicateFiles.Enabled = enabled;
            miAbout.Enabled = enabled;
            lvwFiles.MultiSelect = enabled;
        }

        private void UpdateFileProgressBar(long fullFileSize, long bytesRead)
        {
            if (fullFileSize != 0)
            {
                int percent = (int)(bytesRead * 100 / fullFileSize);

                if (percent > 100)
                    percent = 100;

                if (!_pause)
                    progressBar1.Value = percent;
            }
        }

        private string GetChecksumWithProgress(ParameterizedThreadStart pss, FileInfo fileInfo, IProgress<long> progress = null)
        {
            FileInfoSpeed fis = new FileInfoSpeed { FileInfo = fileInfo, Progress = progress };

            Thread t = new Thread(pss);
            t.Priority = Thread.CurrentThread.Priority;
            t.Start(fis);

            while (!fis.IsDone)
            {
                if (_queueStop)
                {
                    try
                    {
                        t.Abort();
                    }
                    catch (Exception ex)
                    {
                        Trace.WriteLine(ex);
                    }

                    return null;
                }

                Application.DoEvents();
                Thread.Sleep(10);
            }

            if (fis.Exception != null)
                throw fis.Exception;

            return fis.Checksum;
        }

        private static void MD5WithProgress(object obj)
        {
            FileInfoSpeed fis = (FileInfoSpeed)obj;
            try
            {
                fis.Checksum = MD5.Calculate(fis.FileInfo, fis.Progress);
            }
            catch (Exception ex)
            {
                fis.Exception = ex;
            }

            fis.IsDone = true;
        }

        private static void SHA1WithProgress(object obj)
        {
            FileInfoSpeed fis = (FileInfoSpeed)obj;
            try
            {
                fis.Checksum = SHA1.Calculate(fis.FileInfo, fis.Progress);
            }
            catch (Exception ex)
            {
                fis.Exception = ex;
            }

            fis.IsDone = true;
        }

        private static void CRC32WithProgress(object obj)
        {
            FileInfoSpeed fis = (FileInfoSpeed)obj;
            try
            {
                fis.Checksum = CRC32.Calculate(fis.FileInfo, fis.Progress);
            }
            catch (Exception ex)
            {
                fis.Exception = ex;
            }

            fis.IsDone = true;
        }

        private class FileInfoSpeed
        {
            public FileInfo FileInfo { get; set; }
            public string Checksum { get; set; }
            public Exception Exception { get; set; }
            public bool IsDone { get; set; }
            public IProgress<long> Progress { get; set; }
        }

        private void UpdateStatusBar()
        {
            int currentSet = _set_index + 1;
            if (currentSet > _sets.Count)
                currentSet = _sets.Count;

            lblSets.Text = string.Format(Language.MainForm.SetsLabel + " {0:#,0}/{1:#,0}", currentSet, _sets.Count);
            lblParts.Text = string.Format(Language.MainForm.PartsLabel + " {0:#,0}/{1:#,0}", _files_ok + _files_missing + _files_bad, _files_parts);
            lblGood.Text = string.Format(Language.MainForm.GoodLabel + " {0:#,0}", _files_ok);
            lblMissing.Text = string.Format(Language.MainForm.MissingLabel + " {0:#,0}", _files_missing);
            lblBad.Text = string.Format(Language.MainForm.BadLabel + " {0:#,0}", _files_bad);
        }

        private void miUseCachedResults_Click(object sender, EventArgs e)
        {
            Program.Settings.General.UseCachedResults = !Program.Settings.General.UseCachedResults;
            miUseCachedResults.Checked = Program.Settings.General.UseCachedResults;
        }

        private void miFindRenamedFiles_Click(object sender, EventArgs e)
        {
            try
            {
                miFindRenamedFiles.Enabled = false;

                int totalNewOK = 0;
                foreach (ChecksumSet set in _sets)
                {
                    int newOK;
                    FindRenamedFiles(set, out newOK);
                    totalNewOK += newOK;

                    if (newOK != 0)
                    {
                        Program.Settings.Statistics.AddStats(0, 0, 0, newOK, TimeSpan.Zero);
                    }
                }

                SetStatusText(Language.MainForm.Status_Ready);

                MessageBox.Show(string.Format(Language.MainForm.FindRenamedFiles_Message, totalNewOK), Language.MainForm.FindRenamedFiles_Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            finally
            {
                miFindRenamedFiles.Enabled = (_files_missing != 0);
            }
        }

        private void FindRenamedFiles(ChecksumSet set, out int newOK)
        {
            Guard.ArgumentNotNull(set, "set");

            SetStatusText(string.Format(Language.MainForm.Status_FindingRenamesInFile, set.VerificationFileName));
            Application.DoEvents();

            newOK = 0;

            Dictionary<string, string> outOfSetFiles = new Dictionary<string, string>();

            DateTime start = DateTime.Now;

            foreach (ChecksumFile file in set.Files)
            {
                if (file.State == ChecksumFileState.Missing)
                {
                    string fullFileName = Path.Combine(set.Directory, file.FileName);
                    string directory = Path.GetDirectoryName(fullFileName);
                    string lookForExt = Path.GetExtension(fullFileName);
                    //string searchPattern = "*" + Path.GetExtension(fullFileName);

                    if (!Directory.Exists(directory))
                        continue;

                    string[] files = Directory.GetFiles(directory, "*.*", SearchOption.TopDirectoryOnly);
                    foreach (string foundFile in files)
                    {
                        string foundFileExt = Path.GetExtension(foundFile);
                        if (string.Compare(lookForExt, foundFileExt, true) != 0) // extensions don't match
                        {
                            if (!string.IsNullOrEmpty(foundFileExt) && foundFileExt != ".") // and foundFile is not "no extension"
                                continue;
                        }

                        // if the physical file was in our set, don't check it again
                        bool alreadyChecked = false;
                        foreach (ChecksumFile checkedFile in set.Files)
                        {
                            string checkedFullFileName = Path.Combine(set.Directory, checkedFile.FileName);
                            if (string.Compare(checkedFullFileName, foundFile, true) == 0)
                            {
                                alreadyChecked = true;
                                break;
                            }
                        }

                        if (!alreadyChecked)
                        {
                            // check outOfSetFiles
                            string tmpChecksum;
                            if (!outOfSetFiles.TryGetValue(foundFile, out tmpChecksum))
                            {
                                FileInfo fileInfo = TryGetNewFileInfo(foundFile);
                                IProgress<long> progress = new Progress<long>(bytesRead => UpdateFileProgressBar(fileInfo.Length, bytesRead));

                                if (set.Type == ChecksumType.MD5)
                                {
                                    file.CurrentChecksum = GetChecksumWithProgress(MD5WithProgress, fileInfo, progress);
                                    if (string.IsNullOrEmpty(file.CurrentChecksum))
                                        continue;
                                }
                                else if (set.Type == ChecksumType.SFV)
                                {
                                    file.CurrentChecksum = GetChecksumWithProgress(CRC32WithProgress, fileInfo, progress);
                                    if (string.IsNullOrEmpty(file.CurrentChecksum))
                                        continue;
                                }
                                else if (set.Type == ChecksumType.SHA1)
                                {
                                    file.CurrentChecksum = GetChecksumWithProgress(SHA1WithProgress, fileInfo, progress);
                                    if (string.IsNullOrEmpty(file.CurrentChecksum))
                                        continue;
                                }
                                else
                                {
                                    throw new Exception(string.Format("{0} not implemented", set.Type));
                                }

                                outOfSetFiles.Add(foundFile, file.CurrentChecksum);
                            }
                            else
                            {
                                file.CurrentChecksum = tmpChecksum;
                            }

                            if (string.Compare(file.CurrentChecksum, file.OriginalChecksum, true) == 0)
                            {
                                if (Program.Settings.Check.Renaming == CheckRenaming.Lowercase)
                                    fullFileName = fullFileName.ToLower();

                                try
                                {
                                    File.Move(foundFile, fullFileName);
                                }
                                catch (Exception ex)
                                {
                                    Trace.WriteLine(ex); // TODO, write exception to results tab or prompt user
                                }

                                file.State = ChecksumFileState.OK;
                                _files_ok++;
                                _files_missing--;

                                newOK++;

                                UpdateStatusBar();

                                break;
                            }
                        }
                    }
                }
            }

            if (newOK != 0)
            {
                ApplyHideGood();
            }
        }

        private bool GetCreateSet(string ext, List<string> files)
        {
            string path;
            if (files == null)
            {
                if (folderBrowserDialog1.ShowDialog() != DialogResult.OK)
                    return false;

                path = folderBrowserDialog1.SelectedPath;
            }
            else
            {
                path = Path.GetDirectoryName(files[0]);
            }

            string fileName = Path.GetFileName(path);
            if (string.IsNullOrEmpty(fileName))
                fileName = path[0].ToString();
            fileName = string.Format("{0}.{1}", fileName, ext);

            bool checkExists = !Program.Settings.Create.CreateForEachSubDir || !Program.Settings.General.Recursive;

            if (Program.Settings.Create.PromptForFileName)
            {
                saveFileDialog1.DefaultExt = ext;
                saveFileDialog1.FileName = fileName;
                saveFileDialog1.Filter = string.Format("*.{0}|*.{0}", ext);
                saveFileDialog1.InitialDirectory = path;
                saveFileDialog1.OverwritePrompt = checkExists;

                if (saveFileDialog1.ShowDialog() != DialogResult.OK)
                    return false;

                fileName = saveFileDialog1.FileName;
            }
            else
            {
                fileName = Path.Combine(path, fileName);

                if (checkExists && File.Exists(fileName))
                {
                    string message = string.Format(Language.MainForm.OverwriteFile_Message, fileName);
                    if (MessageBox.Show(message, Language.MainForm.OverwriteFile_Title, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                        return false;
                }
            }

            ChecksumType setType;
            if (ext == "md5")
                setType = ChecksumType.MD5;
            else if (ext == "sfv")
                setType = ChecksumType.SFV;
            else if (ext == "sha1")
                setType = ChecksumType.SHA1;
            else
                return false;

            int overwriteCount;
            GetWorkset(fileName, path, setType, files, out overwriteCount);

            if (!checkExists && overwriteCount != 0)
            {
                string message = string.Format(Language.MainForm.OverwriteMultipleFiles_Message, overwriteCount);
                if (MessageBox.Show(message, Language.MainForm.OverwriteMultipleFiles_Title, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                {
                    SetStatusText(Language.MainForm.Status_Ready);
                    _sets.Clear();
                    return false;
                }
            }

            return true;
        }

        private void miNewSFV_Click(object sender, EventArgs e)
        {
            if (!GetCreateSet("sfv", sender as List<string>))
                return;

            CreateSet();
        }

        private void miNewMD5_Click(object sender, EventArgs e)
        {
            if (!GetCreateSet("md5", sender as List<string>))
                return;

            CreateSet();
        }

        private void miNewSHA1_Click(object sender, EventArgs e)
        {
            if (!GetCreateSet("sha1", sender as List<string>))
                return;

            CreateSet();
        }

        private void CreateSet()
        {
            long bytesProcessed = 0;
            _workingOnList = true;

            try
            {
                SetStatusText(Language.MainForm.Status_Working);
                btnPause.Enabled = true;
                btnHide.Enabled = true;

                ToggleMenuItemsEnabled(false, false);

                btnGo.Text = Language.MainForm.StopButton;
                _queueStop = false;
                _pause = false;
                _stopwatch.Restart();

                progressBar1.Value = 0;
                progressBar2.Value = 0;

                _files_parts = 0;
                _files_ok = 0;
                _files_bad = 0;
                _files_missing = 0;
                _totalSizeOfSets = 0;
                foreach (ChecksumSet set in _sets)
                {
                    _files_parts += set.Files.Count;
                    _totalSizeOfSets += set.TotalSize;
                }
                UpdateStatusBar();

                ListViewBeginUpdate();
                try
                {
                    lvwFiles.Items.Clear();
                    lvwFiles.Groups.Clear();

                    foreach (ChecksumSet set in _sets)
                    {
                        ListViewGroup group = new ListViewGroup(lvwFiles.Groups.Count.ToString(), Path.GetFileName(set.VerificationFileName));
                        lvwFiles.Groups.Add(group);

                        foreach (ChecksumFile file in set.Files)
                        {
                            ListViewItem item = new ListViewItem(new[] { file.FileName, file.Guid });
                            item.Tag = file;
                            item.StateImageIndex = 0;
                            item.Group = group;
                            lvwFiles.Items.Add(item);
                        }
                    }
                }
                finally
                {
                    ListViewEndUpdate();
                }

                txtComments.Text = string.Empty;
                if (lvwFiles.Items.Count != 0)
                    lvwFiles.AutoResizeColumn(0, ColumnHeaderAutoResizeStyle.ColumnContent);

                lvwFiles.Focus();
                Application.DoEvents();

                for (_set_index = 0; _set_index < _sets.Count; _set_index++)
                {
                    ChecksumSet set = _sets[_set_index];
                    Program.Settings.AddRecentFile(set.VerificationFileName);

                    int setOKCount = 0;
                    for (int i = 0; i < set.Files.Count; i++)
                    {
                        if (_queueHideGood)
                            ApplyHideGood();

                        if (_pause)
                        {
                            while (_pause && !_queueStop)
                            {
                                if (_queueHideGood)
                                    ApplyHideGood();

                                Thread.Sleep(50);
                                Application.DoEvents();
                            }

                            if (_pause)
                                Unpause();

                            int pauseTotalPercent = _totalSizeOfSets == 0 ? 100 : (int)((bytesProcessed * 100) / _totalSizeOfSets);
                            SetStatusText(string.Format(Language.MainForm.Status_WorkingPercentage, pauseTotalPercent));
                            Application.DoEvents();
                        }

                        if (_queueStop)
                            break;

                        ChecksumFile file = set.Files[i];
                        ListViewItem listItem = lvwFiles.FindItemWithText(file.Guid);

                        progressBar1.Value = 0;
                        listItem.Selected = true;
                        if (Program.Settings.General.AutoScrollFileList)
                            listItem.EnsureVisible();

                        if (!File.Exists(file.FileInfo.FullName))
                        {
                            file.State = ChecksumFileState.Missing;
                            _files_missing++;
                            _queueStop = true;
                        }
                        else
                        {
                            IProgress<long> progress = new Progress<long>(bytesRead => UpdateFileProgressBar(file.FileInfo.Length, bytesRead));

                            if (set.Type == ChecksumType.MD5)
                            {
                                file.CurrentChecksum = GetChecksumWithProgress(MD5WithProgress, file.FileInfo, progress);
                                if (string.IsNullOrEmpty(file.CurrentChecksum))
                                    continue;
                            }
                            else if (set.Type == ChecksumType.SFV)
                            {
                                file.CurrentChecksum = GetChecksumWithProgress(CRC32WithProgress, file.FileInfo, progress);
                                if (string.IsNullOrEmpty(file.CurrentChecksum))
                                    continue;
                            }
                            else if (set.Type == ChecksumType.SHA1)
                            {
                                file.CurrentChecksum = GetChecksumWithProgress(SHA1WithProgress, file.FileInfo, progress);
                                if (string.IsNullOrEmpty(file.CurrentChecksum))
                                    continue;
                            }
                            else
                            {
                                throw new Exception(string.Format("{0} not implemented", set.Type));
                            }

                            file.OriginalChecksum = file.CurrentChecksum;
                            file.State = ChecksumFileState.OK;
                            _files_ok++;
                            setOKCount++;
                        }

                        // update status bar, listview, progressbar
                        UpdateStatusBar();

                        listItem.StateImageIndex = (int)file.State;

                        bytesProcessed += file.FileInfo.Length;

                        UpdateProgressBarsAndText(bytesProcessed);

                        if (Program.Settings.General.HideGoodFiles && file.State == ChecksumFileState.OK)
                            lvwFiles.Items.Remove(listItem);

                        Application.DoEvents();
                    }

                    progressBar1.Value = 100;
                    progressBar2.Value = 100;

                    if (_queueHideGood)
                        ApplyHideGood();

                    if (set.Files.Count == setOKCount)
                    {
                        StringBuilder shabang = new StringBuilder();

                        if (set.Type == ChecksumType.SFV && Program.Settings.Create.SFV32Compatibility)
                        {
                            shabang.AppendLine("; Generated by WIN-SFV32 v1 [added for sfv32 compatibility]");
                        }

                        if (Program.Settings.Comments.WriteComments)
                        {
                            string[] header = Program.Settings.Comments.Header.Split(new[] { Environment.NewLine }, StringSplitOptions.None);
                            string[] content = Program.Settings.Comments.Content.Split(new[] { Environment.NewLine }, StringSplitOptions.None);
                            string[] footer = Program.Settings.Comments.Footer.Split(new[] { Environment.NewLine }, StringSplitOptions.None);

                            DateTime createDateTime = DateTime.Now;
                            foreach (string line in header)
                            {
                                shabang.AppendLine(";" + string.Format(line, createDateTime));
                            }

                            foreach (ChecksumFile file in set.Files)
                            {
                                foreach (string line in content)
                                {
                                    shabang.AppendLine(";" + string.Format(line, file.FileInfo.Length, GetLastWriteTime(file.FileInfo), file.FileName));
                                }
                            }

                            foreach (string line in footer)
                            {
                                shabang.AppendLine(";" + string.Format(line, createDateTime));
                            }
                        }

                        foreach (ChecksumFile file in set.Files)
                        {
                            if (set.Type == ChecksumType.MD5 || set.Type == ChecksumType.SHA1)
                            {
                                if (Program.Settings.Create.MD5SumCompatibility)
                                    shabang.AppendLine(string.Format("{0} *{1}", file.CurrentChecksum, file.FileName));
                                else
                                    shabang.AppendLine(string.Format("{0} {1}", file.CurrentChecksum, file.FileName));
                            }
                            else if (set.Type == ChecksumType.SFV)
                            {
                                shabang.AppendLine(string.Format("{0} {1}", file.FileName, file.CurrentChecksum));
                            }
                            else
                            {
                                throw new Exception(string.Format("{0} not implemented", set.Type));
                            }
                        }

                        string strShaBang = shabang.ToString();

                        File.WriteAllText(set.VerificationFileName, strShaBang, Encoding.GetEncoding(CODE_PAGE));

                        txtComments.Text = strShaBang;
                        set.Comments = strShaBang;
                    }
                }

                _stopwatch.Stop();
                TimeSpan timeSpent = _stopwatch.Elapsed;
                Program.Settings.Statistics.AddStats(_files_parts, _set_index, bytesProcessed / 1024 / 1024, _files_ok, timeSpent);
                Cache.Clean();

                if (Program.Settings.Create.AutoCloseWhenDoneCreating)
                {
                    Close();
                }

                if (Program.Settings.General.FlashWindowWhenDone)
                    FlashWindow(this);
            }
            finally
            {
                TimeSpan totalTime = _stopwatch.Elapsed;
                decimal totalMB = bytesProcessed / 1024.0m / 1024.0m;
                int percentGood = _files_parts == 0 ? 0 : (_files_ok * 100) / _files_parts;
                decimal mbPerSecond = totalTime.TotalSeconds > 0 ? totalMB / (decimal)totalTime.TotalSeconds : totalMB;

                string statusText;
                if (totalTime.TotalSeconds < 600)
                    statusText = string.Format(Language.MainForm.Status_FinishedUnder10Minutes, percentGood, totalMB, totalTime.TotalSeconds, mbPerSecond);
                else
                    statusText = string.Format(Language.MainForm.Status_Finished10MinutesOrMore, percentGood, totalMB, totalTime.Hours, totalTime.Minutes, totalTime.Seconds, mbPerSecond);

                notifyIcon1.ShowBalloonTip(3000, "ilSFV", Language.MainForm.SystemTray_DoneCreating, ToolTipIcon.Info);

                btnPause.Enabled = false;
                btnHide.Enabled = false;
                SetStatusText(statusText);
                //PlayCompleteSound(allOK);

                ToggleMenuItemsEnabled(true, false);

                _workingOnList = false;
                btnGo.Text = Language.MainForm.GoButton;
                _queueStop = false;
            }
        }

        private void btnHide_Click(object sender, EventArgs e)
        {
            notifyIcon1.Visible = true;
            Visible = false;
            if (Program.Settings.General.UseLowPriorityOnHide)
            {
                Thread.CurrentThread.Priority = ThreadPriority.Lowest;
                Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.BelowNormal;
            }
        }

        private void notifyIcon1_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            UnhideFromSystray();
        }

        private void UnhideFromSystray()
        {
            Visible = true;
            notifyIcon1.Visible = false;
            Thread.CurrentThread.Priority = ThreadPriority.Normal;
            Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.Normal;
            Activate();
            if (WindowState == FormWindowState.Minimized)
                WindowState = Program.Settings.General.FormWindowState;
        }

        private bool _pause;
        Stopwatch _stopwatch = new Stopwatch();
        private void btnPause_Click(object sender, EventArgs e)
        {
            if (_pause)
                Unpause();
            else
                Pause();
        }

        private void Pause()
        {
            btnPause.Text = Language.MainForm.ResumeButton;
            _pause = true;
            _stopwatch.Stop();
            SetStatusText(Language.MainForm.Status_Paused);
            btnHide.Enabled = false;
        }

        private void Unpause()
        {
            btnPause.Text = Language.MainForm.PauseButton;
            _pause = false;
            _stopwatch.Start();
            btnHide.Enabled = true;
        }

        private void miExit_Click(object sender, EventArgs e)
        {
            Close();
        }

        private void MainForm_FormClosed(object sender, FormClosedEventArgs e)
        {
            _queueStop = true;
        }

        private void MainForm_Move(object sender, EventArgs e)
        {
            SaveFormSizeAndPosition();
        }

        private void lvwFiles_DragOver(object sender, DragEventArgs e)
        {
            List<FileDrop> list = FileDrop.GetList(e.Data, new[] { ".sfv", ".md5", ".sha1" }, true);
            if (list.Count > 0)
            {
                e.Effect = DragDropEffects.Copy;
            }
        }

        private readonly Timer _dropTimer = new Timer();
        private void lvwFiles_DragDrop(object sender, DragEventArgs e)
        {
            List<FileDrop> list = FileDrop.GetList(e.Data, new[] { ".sfv", ".md5", ".sha1" }, true);
            if (list.Count > 0)
            {
                EngageDropTimer(list.Select(p => p.Path).ToList());
            }
        }

        private void EngageDropTimer(List<string> files)
        {
            _dropTimer.Tick -= _dropTimer_Tick;
            _dropTimer.Tick += _dropTimer_Tick;
            _dropTimer.Interval = 1;
            _dropTimer.Tag = files;
            _dropTimer.Enabled = true;
        }

        private readonly Timer _createTimer = new Timer();
        private void EngageCreateTimer(List<string> files)
        {
            _createTimer.Tick -= _createTimer_Tick;
            _createTimer.Tick += _createTimer_Tick;
            _createTimer.Interval = 1;
            _createTimer.Tag = files;
            _createTimer.Enabled = true;
        }

        private void _createTimer_Tick(object sender, EventArgs e)
        {
            _createTimer.Enabled = false;

            List<string> files = (List<string>)_createTimer.Tag;

            switch (_initialCreateChecksumType)
            {
                case ChecksumType.SFV:
                    miNewSFV_Click(files, EventArgs.Empty);
                    break;

                case ChecksumType.MD5:
                    miNewMD5_Click(files, EventArgs.Empty);
                    break;

                case ChecksumType.SHA1:
                    miNewSHA1_Click(files, EventArgs.Empty);
                    break;

                default:
                    throw new Exception(string.Format("{0} not implemented", _initialCreateChecksumType));
            }
        }

        private void _dropTimer_Tick(object sender, EventArgs e)
        {
            _dropTimer.Enabled = false;

            List<string> files = (List<string>)_dropTimer.Tag;

            if (_workingOnList)
            {
                ListViewBeginUpdate();
                try
                {
                    foreach (string path in files)
                        LoadAndVerifyFile(path, Program.Settings.Check.AutoVerify, true);
                }
                finally
                {
                    ListViewEndUpdate();
                }
            }
            else if (files.Count > 0)
            {
                _workingOnList = true;
                try
                {
                    ListViewBeginUpdate();
                    try
                    {
                        lvwFiles.Items.Clear();

                        _totalSizeOfSets = 0;
                        _files_parts = 0;
                        _sets.Clear();

                        foreach (string path in files)
                            LoadAndVerifyFile(path, false, true);
                    }
                    finally
                    {
                        ListViewEndUpdate();
                    }

                    if (Program.Settings.Check.AutoVerify)
                    {
                        Verify();
                    }
                    else
                    {
                        progressBar1.Value = 0;
                        progressBar2.Value = 0;

                        _set_index = 0;
                        _files_ok = 0;
                        _files_bad = 0;
                        _files_missing = 0;

                        UpdateStatusBar();
                    }
                }
                finally
                {
                    _workingOnList = false;
                }
            }
        }

        private void mnuFile_DropDownOpening(object sender, EventArgs e)
        {
            List<string> paths = Program.Settings.GetRecentFiles().ToList();

            miDocumentSeparator.Visible = false;
            miDocument1.Visible = false;
            miDocument2.Visible = false;
            miDocument3.Visible = false;
            miDocument4.Visible = false;

            if (paths.Count >= 1)
            {
                miDocumentSeparator.Visible = true;
                miDocument1.Text = "&1 " + paths[0];
                miDocument1.Tag = paths[0];
                miDocument1.Visible = true;
            }
            if (paths.Count >= 2)
            {
                miDocument2.Text = "&2 " + paths[1];
                miDocument2.Tag = paths[1];
                miDocument2.Visible = true;
            }
            if (paths.Count >= 3)
            {
                miDocument3.Text = "&3 " + paths[2];
                miDocument3.Tag = paths[2];
                miDocument3.Visible = true;
            }
            if (paths.Count >= 4)
            {
                miDocument4.Text = "&4 " + paths[3];
                miDocument4.Tag = paths[3];
                miDocument4.Visible = true;
            }
        }

        private void miDocument1_Click(object sender, EventArgs e)
        {
            EngageDropTimer(new List<string> { ((ToolStripMenuItem)sender).Tag.ToString() });
        }

        private void miCheckForUpdates_Click(object sender, EventArgs e)
        {
            CheckForUpdates(true);
        }

        private void miRegisterFileTypes_Click(object sender, EventArgs e)
        {
            Cursor.Current = Cursors.WaitCursor;
            try
            {
                Program.RegisterFileTypes(true);
            }
            catch (UnauthorizedAccessException ex)
            {
                Cursor.Current = Cursors.Default;

                MessageBox.Show(string.Format(Language.MainForm.RegisterFileTypesError_Message, ex.Message), Language.MainForm.RegisterFileTypesError_Title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            Cursor.Current = Cursors.Default;
            //MessageBox.Show(".sfv, .md5, .sha1 file types registered.", "Register File Types", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void miCopyFileNames_Click(object sender, EventArgs e)
        {
            Cursor.Current = Cursors.WaitCursor;
            StringBuilder sb = new StringBuilder();
            foreach (ListViewItem item in lvwFiles.SelectedItems)
            {
                ChecksumFile file = (ChecksumFile)item.Tag;
                if (lvwFiles.SelectedItems.Count == 1)
                    sb.Append(Path.GetFileName(file.FileName));
                else
                    sb.AppendLine(Path.GetFileName(file.FileName));
            }
            Clipboard.SetText(sb.ToString());
            Cursor.Current = Cursors.WaitCursor;
        }

        private void miCopyPathAndFileNames_Click(object sender, EventArgs e)
        {
            Cursor.Current = Cursors.WaitCursor;
            StringBuilder sb = new StringBuilder();
            foreach (ListViewItem item in lvwFiles.SelectedItems)
            {
                ChecksumFile file = (ChecksumFile)item.Tag;
                if (lvwFiles.SelectedItems.Count == 1)
                    sb.Append(Path.Combine(file.Set.Directory, file.FileName));
                else
                    sb.AppendLine(Path.Combine(file.Set.Directory, file.FileName));
            }
            Clipboard.SetText(sb.ToString());
            Cursor.Current = Cursors.WaitCursor;
        }

        private void miCopyCurrentChecksum_Click(object sender, EventArgs e)
        {
            Cursor.Current = Cursors.WaitCursor;
            StringBuilder sb = new StringBuilder();
            foreach (ListViewItem item in lvwFiles.SelectedItems)
            {
                ChecksumFile file = (ChecksumFile)item.Tag;
                if (lvwFiles.SelectedItems.Count == 1)
                    sb.Append(file.CurrentChecksum);
                else
                    sb.AppendLine(file.CurrentChecksum);
            }
            Clipboard.SetText(sb.ToString());
            Cursor.Current = Cursors.WaitCursor;
        }

        private void miCopyOriginalChecksum_Click(object sender, EventArgs e)
        {
            Cursor.Current = Cursors.WaitCursor;
            StringBuilder sb = new StringBuilder();
            foreach (ListViewItem item in lvwFiles.SelectedItems)
            {
                ChecksumFile file = (ChecksumFile)item.Tag;
                if (lvwFiles.SelectedItems.Count == 1)
                    sb.Append(file.OriginalChecksum);
                else
                    sb.AppendLine(file.OriginalChecksum);
            }
            Clipboard.SetText(sb.ToString());
            Cursor.Current = Cursors.WaitCursor;
        }

        private void contextMenuStrip1_Opening(object sender, CancelEventArgs e)
        {
            if (_workingOnList || lvwFiles.SelectedItems.Count == 0)
            {
                e.Cancel = true;
                return;
            }

            miCopyCurrentChecksum.Visible = false;
            miCopyOriginalChecksum.Visible = false;

            bool showSep = false;
            if (lvwFiles.SelectedItems.Count == 1)
            {
                ListViewItem item = lvwFiles.SelectedItems[0];
                ChecksumFile file = (ChecksumFile)item.Tag;

                if (!string.IsNullOrEmpty(file.CurrentChecksum))
                {
                    miCopyCurrentChecksum.Text = string.Format(Language.MainForm.CopyCurrentChecksumContextMenu, file.CurrentChecksum);
                    miCopyCurrentChecksum.Visible = true;
                    showSep = true;
                }

                if (!string.IsNullOrEmpty(file.OriginalChecksum))
                {
                    miCopyOriginalChecksum.Text = string.Format(Language.MainForm.CopyOriginalChecksumContextMenu, file.OriginalChecksum);
                    miCopyOriginalChecksum.Visible = true;
                    showSep = true;
                }
            }

            miContextMenuSeparator.Visible = showSep;
        }

        private void lvwFiles_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (_workingOnList)
                return;

            if (lvwFiles.SelectedItems.Count == 1)
            {
                ChecksumFile file = ((ChecksumFile)lvwFiles.SelectedItems[0].Tag);
                txtComments.Text = file.Set.Comments;
                txtQuickSFV.Text = file.Set.QuickSfvAnalysis;
                if (string.IsNullOrEmpty(file.Set.QuickSfvAnalysis))
                    tpQuickSFV.Parent = null;
                else
                    tpQuickSFV.Parent = tabControl1;
            }
            else
            {
                txtComments.Text = string.Empty;
                txtQuickSFV.Text = string.Empty;
                tpQuickSFV.Parent = null;
            }
        }

        private int _listViewUpdate;
        private void ListViewBeginUpdate()
        {
            if (_listViewUpdate == 0)
                lvwFiles.BeginUpdate();
            _listViewUpdate++;
        }

        private void ListViewEndUpdate()
        {
            _listViewUpdate--;
            if (_listViewUpdate == 0)
                lvwFiles.EndUpdate();
        }

        private static DateTime GetLastWriteTime(FileSystemInfo fileInfo)
        {
            try
            {
                return fileInfo.LastWriteTime;
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex);
                return DateTime.Now;
            }
        }

        private static DateTime GetLastWriteTimeUtc(FileSystemInfo fileInfo)
        {
            try
            {
                return fileInfo.LastWriteTimeUtc;
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex);
                return DateTime.Now;
            }
        }

        private void miFindDuplicateFiles_Click(object sender, EventArgs e)
        {
            bool ok = false;
            try
            {
                List<string> fileNames = GetChecksumFiles(false);
                if (fileNames == null || fileNames.Count != 1)
                    return;

                if (!LoadAndVerifyFile(fileNames[0], false, false))
                    return;

                if (_sets.Count != 1)
                    return;

                ok = true;
            }
            finally
            {
                if (!ok)
                {
                    Cursor.Current = Cursors.WaitCursor;
                    _sets.Clear();
                    lvwFiles.BeginUpdate();
                    try
                    {
                        lvwFiles.Items.Clear();
                    }
                    finally
                    {
                        lvwFiles.EndUpdate();
                    }
                    Cursor.Current = Cursors.Default;
                }
                SetStatusText(Language.MainForm.Status_Ready);
            }

            Cursor.Current = Cursors.WaitCursor;
            ChecksumSet set = _sets[0];
            using (RemoveDuplicatesForm form = new RemoveDuplicatesForm(set))
            {
                Cursor.Current = Cursors.Default;
                form.ShowDialog();
            }

            Cursor.Current = Cursors.WaitCursor;
            _sets.Clear();
            lvwFiles.BeginUpdate();
            try
            {
                lvwFiles.Items.Clear();
            }
            finally
            {
                lvwFiles.EndUpdate();
            }
            Cursor.Current = Cursors.Default;
        }

        private void miTruncateFileNames_Click(object sender, EventArgs e)
        {
            string strMaxLength;
            if (!GetInputForm.ShowForm(Language.MainForm.TruncateFileNames_MaxLength, Language.MainForm.TruncateFileNames_MaxLength, out strMaxLength))
                return;

            int maxLength;
            if (!int.TryParse(strMaxLength, out maxLength))
                return;

            if (maxLength < 12)
            {
                MessageBox.Show(Language.MainForm.TruncateFileNames_MinimumLengthIs12, "", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            if (folderBrowserDialog1.ShowDialog() != DialogResult.OK)
                return;

            string path = folderBrowserDialog1.SelectedPath;

            Dictionary<string, List<string>> dict = GetFilesAllDirectories(path);

            SetStatusText(Language.MainForm.Status_LookingForLongFileNames);

            int count = 0;
            foreach (KeyValuePair<string, List<string>> kvp in dict)
            {
                foreach (string fullPath in kvp.Value)
                {
                    string fileName = Path.GetFileName(fullPath);
                    if (fileName.Length > maxLength)
                    {
                        string ext = Path.GetExtension(fileName);
                        string nameWithoutExt = Path.GetFileNameWithoutExtension(fileName);
                        int newLength = maxLength - ext.Length;
                        nameWithoutExt = nameWithoutExt.Substring(0, newLength);
                        string newName = nameWithoutExt + ext;
                        string newFullPath = Path.Combine(kvp.Key, newName);

                        SetStatusText(string.Format(Language.MainForm.Status_Renaming, fileName, newName));

                        File.Move(fullPath, newFullPath);
                        count++;
                    }
                }
            }

            SetStatusText(Language.MainForm.Status_Ready);

            MessageBox.Show(string.Format(Language.MainForm.TruncateFileNames_FilesRenamed_Message, count), "", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void SetLanguage()
        {
            var p = Language.MainForm;

            // File
            mnuFile.Text = p.Menu_File;
            miNewSFV.Text = p.Menu_File_NewSFVFile;
            miNewMD5.Text = p.Menu_File_NewMD5File;
            miNewSHA1.Text = p.Menu_File_NewSHA1File;
            miOpen.Text = p.Menu_File_Open;
            miPreferences.Text = p.Menu_File_Preferences;
            miCheckForUpdates.Text = p.Menu_File_CheckForUpdates;
            miExit.Text = p.Menu_File_Exit;

            // Legend
            mnuLegend.Text = p.Menu_Legend;
            miFileOK.Text = p.Menu_Legend_FileOK;
            miFileBad.Text = p.Menu_Legend_FileBad;
            miFileNotFound.Text = p.Menu_Legend_FileNotFound;
            miFileUntested.Text = p.Menu_Legend_FileUntestedUnknown;

            // Tools
            mnuTools.Text = p.Menu_Tools;
            miFindRenamedFiles.Text = p.Menu_Tools_FindRenamedFiles;
            miUseCachedResults.Text = p.Menu_Tools_UseCachedResults;
            miFindDuplicateFiles.Text = p.Menu_Tools_FindDeleteDuplicateFilesUsingChecksum;
            miTruncateFileNames.Text = p.Menu_Tools_TruncateFileNames;
            miRegisterFileTypes.Text = p.Menu_Tools_RegisterFileTypes;

            // View
            mnuView.Text = p.Menu_View;
            miHideGood.Text = p.Menu_View_HideGood;
            miCommentResultPane.Text = p.Menu_View_CommentResultPane;

            // Help
            mnuHelp.Text = p.Menu_Help;
            miAbout.Text = p.Menu_Help_About;

            // Headers
            colFilename.Text = p.FileNameColumnHeader;
            tpComments.Text = p.CommentsTabHeader;

            // Status bar labels
            lblSets.Text = p.SetsLabel;
            lblParts.Text = p.PartsLabel;
            lblGood.Text = p.GoodLabel;
            lblBad.Text = Language.MainForm.BadLabel;
            lblMissing.Text = p.MissingLabel;

            // Buttons
            chkHideGood.Text = p.HideGoodCheckBox;
            btnPause.Text = p.PauseButton;
            btnHide.Text = p.HideButton;
            btnGo.Text = p.GoButton;

            // Dialogs
            folderBrowserDialog1.Description = p.FolderBrowseDialog_Title;

            SetStatusText(p.Status_Ready);

            Application.DoEvents();

            progressBar1.Width = chkHideGood.Left - 16;
        }

        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if (keyData == Keys.Escape)
            {
                if (_workingOnList)
                {
                    _queueStop = true;
                }
                else
                {
                    this.Close();
                }
                return true;
            }
            return base.ProcessCmdKey(ref msg, keyData);
        }
    }
}
