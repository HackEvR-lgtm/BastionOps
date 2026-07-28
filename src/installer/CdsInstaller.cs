using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.ServiceProcess;
using System.Windows.Forms;
using Microsoft.Win32;

namespace CdsInstaller
{
    static class Program
    {
        [STAThread]
        static void Main()
        {
            if (!IsAdministrator())
            {
                RestartAsAdmin();
                return;
            }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new InstallerForm());
        }

        static bool IsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        static void RestartAsAdmin()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = Application.ExecutablePath,
                    UseShellExecute = true,
                    Verb = "runas"
                };
                Process.Start(psi);
            }
            catch
            {
                MessageBox.Show("This installer requires Administrator privileges.", "Permission Required", 
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
    }

    public class InstallerForm : Form
    {
        private Label statusLabel;
        private Button installButton;
        private Button uninstallButton;
        private PictureBox logoBox;
        private const string CDS_PATH = @"C:\ProgramData\CDS";
        private const string SERVICE_NAME = "CDSProtectionService";

        public InstallerForm()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            this.Text = "CDS v2.1 Installer - BastionOps";
            this.Size = new System.Drawing.Size(500, 400);
            this.FormBorderStyle = FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;
            this.StartPosition = FormStartPosition.CenterScreen;

            logoBox = new PictureBox
            {
                Size = new System.Drawing.Size(120, 120),
                Location = new System.Drawing.Point(190, 20),
                SizeMode = PictureBoxSizeMode.StretchImage,
                BackColor = System.Drawing.Color.FromArgb(30, 30, 30)
            };
            
            using (Graphics g = logoBox.CreateGraphics())
            {
                g.Clear(System.Drawing.Color.FromArgb(30, 30, 30));
                using (var brush = new SolidBrush(System.Drawing.Color.LimeGreen))
                {
                    g.DrawString("🛡️", new System.Drawing.Font("Segoe UI", 48), brush, new System.Drawing.PointF(30, 20));
                }
            }

            Label titleLabel = new Label
            {
                Text = "Capability Denial System",
                Font = new System.Drawing.Font("Segoe UI", 16, System.Drawing.FontStyle.Bold),
                AutoSize = true,
                Location = new System.Drawing.Point(140, 150)
            };

            statusLabel = new Label
            {
                Text = "Ready to install protection",
                Font = new System.Drawing.Font("Segoe UI", 10),
                AutoSize = true,
                Location = new System.Drawing.Point(160, 185),
                ForeColor = System.Drawing.Color.Gray
            };

            installButton = new Button
            {
                Text = "Instalar Protección",
                Size = new System.Drawing.Size(180, 50),
                Location = new System.Drawing.Point(160, 230),
                Font = new System.Drawing.Font("Segoe UI", 12, System.Drawing.FontStyle.Bold),
                BackColor = System.Drawing.Color.LimeGreen,
                ForeColor = System.Drawing.Color.White,
                FlatStyle = FlatStyle.Flat
            };
            installButton.FlatAppearance.BorderSize = 0;
            installButton.Click += InstallButton_Click;

            uninstallButton = new Button
            {
                Text = "Desinstalar",
                Size = new System.Drawing.Size(180, 40),
                Location = new System.Drawing.Point(160, 290),
                Font = new System.Drawing.Font("Segoe UI", 10),
                BackColor = System.Drawing.Color.DarkRed,
                ForeColor = System.Drawing.Color.White,
                FlatStyle = FlatStyle.Flat
            };
            uninstallButton.FlatAppearance.BorderSize = 0;
            uninstallButton.Click += UninstallButton_Click;

            this.Controls.Add(logoBox);
            this.Controls.Add(titleLabel);
            this.Controls.Add(statusLabel);
            this.Controls.Add(installButton);
            this.Controls.Add(uninstallButton);
        }

        private void InstallButton_Click(object sender, EventArgs e)
        {
            SetStatus("Checking system requirements...", System.Drawing.Color.Blue);
            installButton.Enabled = false;

            try
            {
                // Check Test Signing Mode
                if (!IsTestSigningEnabled())
                {
                    var result = MessageBox.Show(
                        "Windows Test Signing mode is disabled. The kernel driver requires Test Signing to be enabled.\n\n" +
                        "Would you like to enable it now? This will require a system reboot.",
                        "Test Signing Required",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Warning);

                    if (result == DialogResult.Yes)
                    {
                        EnableTestSigning();
                        SetStatus("Test Signing enabled. Please reboot and run installer again.", System.Drawing.Color.Orange);
                        installButton.Enabled = true;
                        return;
                    }
                    else
                    {
                        SetStatus("Installation cancelled. Test Signing required.", System.Drawing.Color.Red);
                        installButton.Enabled = true;
                        return;
                    }
                }

                SetStatus("Installing CDS Protection...", System.Drawing.Color.Blue);

                // Create installation directory
                if (!Directory.Exists(CDS_PATH))
                {
                    Directory.CreateDirectory(CDS_PATH);
                }

                // Find and copy daemon executable
                string exeSource = FindDaemonExecutable();
                string exeDest = Path.Combine(CDS_PATH, "CapabilityDenialSystem.exe");
                
                if (File.Exists(exeSource))
                {
                    File.Copy(exeSource, exeDest, true);
                    SetStatus("Copying daemon files...", System.Drawing.Color.Blue);
                }

                // Copy whitelist if exists
                string whitelistSource = Path.Combine(Path.GetDirectoryName(exeSource), "whitelist.json");
                if (File.Exists(whitelistSource))
                {
                    File.Copy(whitelistSource, Path.Combine(CDS_PATH, "whitelist.json"), true);
                }

                // Create Windows Service
                SetStatus("Creating Windows Service...", System.Drawing.Color.Blue);
                CreateService(exeDest);

                // Configure Firewall Rules
                SetStatus("Configuring Firewall Rules...", System.Drawing.Color.Blue);
                ConfigureFirewallRules(exeDest);

                // Start Service
                SetStatus("Starting Protection Service...", System.Drawing.Color.Blue);
                StartService();

                SetStatus("✓ Installation Complete! System is now protected.", System.Drawing.Color.LimeGreen);
                MessageBox.Show("CDS Protection has been successfully installed!\n\nThe system is now protected against APTs and RATs.", 
                    "Installation Successful", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                SetStatus($"Installation failed: {ex.Message}", System.Drawing.Color.Red);
                MessageBox.Show($"Installation failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                installButton.Enabled = true;
            }
        }

        private void UninstallButton_Click(object sender, EventArgs e)
        {
            var result = MessageBox.Show(
                "Are you sure you want to uninstall CDS Protection?\n\nThis will remove all protection and leave your system vulnerable.",
                "Confirm Uninstall",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);

            if (result != DialogResult.Yes) return;

            uninstallButton.Enabled = false;
            SetStatus("Uninstalling...", System.Drawing.Color.Orange);

            try
            {
                StopService();
                DeleteService();
                RemoveFirewallRules();

                if (Directory.Exists(CDS_PATH))
                {
                    Directory.Delete(CDS_PATH, true);
                }

                SetStatus("✓ Uninstallation Complete", System.Drawing.Color.LimeGreen);
                MessageBox.Show("CDS Protection has been uninstalled.", "Uninstall Complete", 
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                SetStatus($"Uninstall failed: {ex.Message}", System.Drawing.Color.Red);
                MessageBox.Show($"Uninstall failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                uninstallButton.Enabled = true;
            }
        }

        private void SetStatus(string text, System.Drawing.Color color)
        {
            if (statusLabel.InvokeRequired)
            {
                statusLabel.Invoke(new Action(() => { statusLabel.Text = text; statusLabel.ForeColor = color; }));
            }
            else
            {
                statusLabel.Text = text;
                statusLabel.ForeColor = color;
            }
        }

        private bool IsTestSigningEnabled()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c bcdedit /enum | findstr /i \"testsigning\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (var proc = Process.Start(psi))
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit();
                    return output.IndexOf("Yes", StringComparison.OrdinalIgnoreCase) >= 0;
                }
            }
            catch
            {
                return false;
            }
        }

        private void EnableTestSigning()
        {
            var psi = new ProcessStartInfo
            {
                FileName = "bcdedit.exe",
                Arguments = "/set testsigning on",
                UseShellExecute = true,
                Verb = "runas"
            };
            Process.Start(psi)?.WaitForExit();
        }

        private string FindDaemonExecutable()
        {
            string[] possiblePaths = new[]
            {
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CapabilityDenialSystem.exe"),
                Path.Combine(Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory).FullName, "usermode", "bin", "Release", "net8.0-windows", "win-x64", "CapabilityDenialSystem.exe"),
                Path.Combine(Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory).FullName, "usermode", "bin", "Release", "net8.0-windows", "CapabilityDenialSystem.exe")
            };

            foreach (string path in possiblePaths)
            {
                if (File.Exists(path)) return path;
            }

            throw new FileNotFoundException("Could not find CapabilityDenialSystem.exe. Please ensure the daemon is built.");
        }

        private void CreateService(string exePath)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"create {SERVICE_NAME} binPath= \"{exePath}\" start= auto DisplayName= \"CDS Protection Service\"",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (var proc = Process.Start(psi))
            {
                proc.WaitForExit();
                if (proc.ExitCode != 0 && proc.ExitCode != 1073) // 1073 = service already exists
                {
                    throw new Exception($"Failed to create service. Exit code: {proc.ExitCode}");
                }
            }
        }

        private void DeleteService()
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"delete {SERVICE_NAME}",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (var proc = Process.Start(psi))
            {
                proc.WaitForExit();
            }
        }

        private void StartService()
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"start {SERVICE_NAME}",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (var proc = Process.Start(psi))
            {
                proc.WaitForExit(5000);
            }
        }

        private void StopService()
        {
            try
            {
                using (var sc = new ServiceController(SERVICE_NAME))
                {
                    if (sc.Status == ServiceControllerStatus.Running)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
                    }
                }
            }
            catch { }
        }

        private void ConfigureFirewallRules(string exePath)
        {
            string rulesScript = $@"
                netsh advfirewall firewall add rule name=""CDS_Daemon_Allow"" dir=in action=allow program=""{exePath}"" enable=yes;
                netsh advfirewall firewall add rule name=""CDS_Daemon_Out"" dir=out action=allow program=""{exePath}"" enable=yes;
            ";
            ExecutePowerShell(rulesScript);
        }

        private void RemoveFirewallRules()
        {
            string rulesScript = @"
                netsh advfirewall firewall delete rule name=""CDS_Daemon_Allow"";
                netsh advfirewall firewall delete rule name=""CDS_Daemon_Out"";
            ";
            ExecutePowerShell(rulesScript);
        }

        private void ExecutePowerShell(string script)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-ExecutionPolicy Bypass -NoProfile -Command \"{script}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (var proc = Process.Start(psi))
            {
                proc.WaitForExit(10000);
            }
        }
    }
}
