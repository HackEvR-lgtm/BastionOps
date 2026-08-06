using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace CapabilityDenialSystem
{
    /// <summary>
    /// System Tray Dashboard for CDS v2.1
    /// Provides user-friendly control panel with panic mode, status monitoring, and log access.
    /// </summary>
    public class CdsTrayApp : ApplicationContext
    {
        private NotifyIcon _trayIcon;
        private ContextMenuStrip _contextMenu;
        private ToolStripMenuItem _statusMenuItem;
        private ToolStripMenuItem _panicMenuItem;
        private ToolStripMenuItem _logsMenuItem;
        private ToolStripMenuItem _exitMenuItem;
        private Form _dashboardForm;
        private Timer _statusUpdateTimer;
        private bool _isProtected = true;
        private int _processesMonitored = 0;
        private int _threatsBlockedToday = 0;
        private const string LOG_FILE_PATH = @"C:\ProgramData\CDS\audit.log";

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool DestroyIcon(IntPtr hIcon);

        public CdsTrayApp()
        {
            InitializeTrayIcon();
            InitializeContextMenu();
            InitializeDashboardForm();
            StartStatusUpdates();
        }

        private void InitializeTrayIcon()
        {
            _trayIcon = new NotifyIcon
            {
                Text = "CDS Protection - Active",
                Visible = true,
                Icon = CreateShieldIcon(),
                BalloonTipTitle = "CDS Protection",
                BalloonTipText = "System is protected",
                BalloonTipIcon = ToolTipIcon.Info
            };

            _trayIcon.DoubleClick += (s, e) => ShowDashboard();
            _trayIcon.BalloonTipClicked += (s, e) => ShowDashboard();
        }

        private Icon CreateShieldIcon()
        {
            using Bitmap bmp = new Bitmap(32, 32);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.Clear(Color.Transparent);
                
                // Shield background
                using (Brush shieldBrush = new SolidBrush(Color.FromArgb(0, 100, 0)))
                {
                    g.FillEllipse(shieldBrush, 2, 2, 28, 28);
                }
                
                // Shield border
                using (Pen borderPen = new Pen(Color.LimeGreen, 2))
                {
                    g.DrawEllipse(borderPen, 2, 2, 28, 28);
                }
                
                // Check mark
                using (Pen checkPen = new Pen(Color.White, 3))
                {
                    g.DrawLine(checkPen, 10, 16, 14, 22);
                    g.DrawLine(checkPen, 14, 22, 22, 10);
                }
            }
            IntPtr hIcon = bmp.GetHicon();
            try
            {
                return Icon.FromHandle(hIcon);
            }
            finally
            {
                DestroyIcon(hIcon);
            }
        }

        private void InitializeContextMenu()
        {
            _contextMenu = new ContextMenuStrip();

            _statusMenuItem = new ToolStripMenuItem
            {
                Text = "Estado: Protegiendo",
                ForeColor = Color.LimeGreen,
                Font = new Font("Segoe UI", 9, FontStyle.Bold),
                Enabled = false
            };

            _panicMenuItem = new ToolStripMenuItem
            {
                Text = "🚨 ACTIVAR MODO PÁNICO",
                ForeColor = Color.Red,
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            _panicMenuItem.Click += PanicMenuItem_Click;

            _logsMenuItem = new ToolStripMenuItem
            {
                Text = "Ver Logs en Tiempo Real"
            };
            _logsMenuItem.Click += LogsMenuItem_Click;

            ToolStripMenuItem dashboardMenuItem = new ToolStripMenuItem
            {
                Text = "Abrir Dashboard"
            };
            dashboardMenuItem.Click += (s, e) => ShowDashboard();

            _exitMenuItem = new ToolStripMenuItem
            {
                Text = "Salir"
            };
            _exitMenuItem.Click += ExitMenuItem_Click;

            _contextMenu.Items.AddRange(new ToolStripItem[] 
            { 
                _statusMenuItem, 
                new ToolStripSeparator(),
                _panicMenuItem, 
                _logsMenuItem, 
                dashboardMenuItem,
                new ToolStripSeparator(),
                _exitMenuItem 
            });

            _trayIcon.ContextMenuStrip = _contextMenu;
        }

        private void InitializeDashboardForm()
        {
            _dashboardForm = new Form
            {
                Text = "CDS Protection Dashboard",
                Size = new Size(450, 350),
                FormBorderStyle = FormBorderStyle.FixedSingle,
                MaximizeBox = false,
                MinimizeBox = false,
                StartPosition = FormStartPosition.CenterScreen,
                TopMost = true
            };

            Panel headerPanel = new Panel
            {
                Dock = DockStyle.Top,
                Height = 80,
                BackColor = Color.FromArgb(30, 30, 30)
            };

            Label titleLabel = new Label
            {
                Text = "🛡️ CDS Protection Dashboard",
                Font = new Font("Segoe UI", 16, FontStyle.Bold),
                ForeColor = Color.LimeGreen,
                AutoSize = true,
                Location = new Point(20, 20)
            };

            Panel statsPanel = new Panel
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(20)
            };

            Panel processesPanel = CreateStatLabel("Processes Monitored:", "0");
            processesPanel.Location = new Point(20, 20);
            processesPanel.Name = "processesPanel";

            Panel threatsPanel = CreateStatLabel("Threats Blocked Today:", "0");
            threatsPanel.Location = new Point(20, 70);
            threatsPanel.Name = "threatsPanel";

            Panel networkPanel = CreateStatLabel("Network Status:", "Protected");
            networkPanel.Location = new Point(20, 120);
            networkPanel.Name = "networkPanel";

            Button panicButton = new Button
            {
                Text = "🚨 MODO PÁNICO",
                Size = new Size(200, 50),
                Location = new Point(20, 180),
                Font = new Font("Segoe UI", 12, FontStyle.Bold),
                BackColor = Color.DarkRed,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            panicButton.FlatAppearance.BorderSize = 0;
            panicButton.Click += (s, e) => TriggerPanicMode();

            Button closeButton = new Button
            {
                Text = "Cerrar",
                Size = new Size(100, 35),
                Location = new Point(240, 180),
                Font = new Font("Segoe UI", 10),
                BackColor = Color.Gray,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            closeButton.FlatAppearance.BorderSize = 0;
            closeButton.Click += (s, e) => _dashboardForm.Hide();

            statsPanel.Controls.Add(processesPanel);
            statsPanel.Controls.Add(threatsPanel);
            statsPanel.Controls.Add(networkPanel);
            statsPanel.Controls.Add(panicButton);
            statsPanel.Controls.Add(closeButton);

            headerPanel.Controls.Add(titleLabel);
            _dashboardForm.Controls.Add(statsPanel);
            _dashboardForm.Controls.Add(headerPanel);

            _dashboardForm.FormClosing += (s, e) =>
            {
                e.Cancel = true;
                _dashboardForm.Hide();
            };
        }

        private Panel CreateStatLabel(string labelText, string value)
        {
            Panel container = new Panel
            {
                Size = new Size(380, 40),
                BackColor = Color.FromArgb(240, 240, 240)
            };

            Label label = new Label
            {
                Text = $"{labelText}  {value}",
                Font = new Font("Segoe UI", 11),
                AutoSize = true,
                Location = new Point(10, 10)
            };

            container.Controls.Add(label);
            return container;
        }

        private void StartStatusUpdates()
        {
            _statusUpdateTimer = new Timer { Interval = 5000 };
            _statusUpdateTimer.Tick += (s, e) => UpdateStatus();
            _statusUpdateTimer.Start();
            
            // Initial update
            UpdateStatus();
        }

        private void UpdateStatus()
        {
            try
            {
                // Simulate getting real stats (in production, this would query the daemon)
                _processesMonitored = Process.GetProcesses().Length;
                
                // Try to read threats from audit log
                if (File.Exists(LOG_FILE_PATH))
                {
                    var lines = File.ReadAllLines(LOG_FILE_PATH);
                    _threatsBlockedToday = 0;
                    foreach (var line in lines)
                    {
                        if (line.Contains("THREAT_BLOCKED") || line.Contains("INJECTION_ATTEMPT"))
                        {
                            _threatsBlockedToday++;
                        }
                    }
                }

                // Update UI
                _statusMenuItem.Text = _isProtected ? "Estado: Protegiendo" : "Estado: Vulnerable";
                _statusMenuItem.ForeColor = _isProtected ? Color.LimeGreen : Color.Red;
                _trayIcon.Text = _isProtected ? "CDS Protection - Active" : "CDS Protection - Inactive";

                // Update dashboard if visible
                if (_dashboardForm.Visible)
                {
                    UpdateDashboardStats();
                }
            }
            catch
            {
                // Silently fail on status update errors
            }
        }

        private void UpdateDashboardStats()
        {
            foreach (Control ctrl in _dashboardForm.Controls)
            {
                if (ctrl is Panel panel)
                {
                    foreach (Control child in panel.Controls)
                    {
                        if (child is Panel statPanel)
                        {
                            foreach (Control inner in statPanel.Controls)
                            {
                                if (inner is Label lbl)
                                {
                                    if (statPanel.Name == "processesPanel")
                                    {
                                        lbl.Text = $"Processes Monitored:  {_processesMonitored}";
                                    }
                                    else if (statPanel.Name == "threatsPanel")
                                    {
                                        lbl.Text = $"Threats Blocked Today:  {_threatsBlockedToday}";
                                    }
                                    else if (statPanel.Name == "networkPanel")
                                    {
                                        lbl.Text = $"Network Status:  {(_isProtected ? "Protected" : "Unprotected")}";
                                        lbl.ForeColor = _isProtected ? Color.LimeGreen : Color.Red;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        private void ShowDashboard()
        {
            UpdateDashboardStats();
            _dashboardForm.Show();
            _dashboardForm.Activate();
        }

        private void PanicMenuItem_Click(object sender, EventArgs e)
        {
            TriggerPanicMode();
        }

        private void TriggerPanicMode()
        {
            var result = MessageBox.Show(
                "⚠️ CRITICAL WARNING ⚠️\n\n" +
                "Activating PANIC MODE will immediately block ALL network traffic (inbound and outbound).\n\n" +
                "This should only be used in emergency situations when an active threat is detected.\n\n" +
                "Do you want to continue?",
                "Confirm Panic Mode",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);

            if (result == DialogResult.Yes)
            {
                try
                {
                    string panicScript = @"
                        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block -Enabled True;
                        Get-NetFirewallRule | Where-Object { $_.DisplayName -notmatch '^CDS_' } | Disable-NetFirewallRule;
                    ";

                    var psi = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = $"-ExecutionPolicy Bypass -NoProfile -Command \"{panicScript}\"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using (var proc = Process.Start(psi))
                    {
                        proc?.WaitForExit(10000);
                    }

                    _trayIcon.ShowBalloonTip(5000, "PANIC MODE ACTIVATED", 
                        "All network traffic has been blocked. System is isolated.", ToolTipIcon.Warning);
                    
                    MessageBox.Show("PANIC MODE ACTIVATED\n\nAll network traffic is now blocked.\nTo restore network access, restart the computer or manually re-enable firewall rules.",
                        "Panic Mode Active", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to activate panic mode: {ex.Message}", "Error", 
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void LogsMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                if (File.Exists(LOG_FILE_PATH))
                {
                    Process.Start("notepad.exe", LOG_FILE_PATH);
                }
                else
                {
                    // Try alternative log locations
                    string altLogPath = Path.Combine(Environment.CurrentDirectory, "audit.log");
                    if (File.Exists(altLogPath))
                    {
                        Process.Start("notepad.exe", altLogPath);
                    }
                    else
                    {
                        MessageBox.Show("No audit log file found.", "Logs", 
                            MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Could not open logs: {ex.Message}", "Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ExitMenuItem_Click(object sender, EventArgs e)
        {
            var result = MessageBox.Show(
                "Are you sure you want to exit CDS Protection?\n\nThis will stop all monitoring and leave your system vulnerable.",
                "Confirm Exit",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);

            if (result == DialogResult.Yes)
            {
                _statusUpdateTimer.Stop();
                _trayIcon.Visible = false;
                Application.Exit();
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _statusUpdateTimer?.Dispose();
                _trayIcon?.Dispose();
                _contextMenu?.Dispose();
                _dashboardForm?.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
