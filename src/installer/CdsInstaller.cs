using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.ServiceProcess;
using System.Windows.Forms;

namespace CdsInstaller
{
    static class Program
    {
        [STAThread]
        static void Main()
        {
            if (!IsAdministrator())
            {
                MessageBox.Show("Este instalador requiere privilegios de Administrador.", "Error de Permisos", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
    }

    public class InstallerForm : Form
    {
        private Label lblStatus;
        private ProgressBar progressBar;
        private Button btnInstall;
        private Button btnUninstall;

        private readonly string installDir = @"C:\ProgramData\CDS";
        private readonly string daemonServiceName = "CDSDaemon";

        public InstallerForm()
        {
            this.Text = "BastionOps v2.1 - Instalador (User-Mode)";
            this.Size = new System.Drawing.Size(500, 280);
            this.FormBorderStyle = FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;
            this.StartPosition = FormStartPosition.CenterScreen;

            lblStatus = new Label { Left = 20, Top = 20, Width = 440, Height = 40, Font = new System.Drawing.Font("Segoe UI", 10, System.Drawing.FontStyle.Bold) };
            progressBar = new ProgressBar { Left = 20, Top = 70, Width = 440, Height = 20 };
            btnInstall = new Button { Text = "Instalar BastionOps (One-Click)", Left = 120, Top = 120, Width = 240, Height = 40 };
            btnUninstall = new Button { Text = "Desinstalar", Left = 120, Top = 170, Width = 240, Height = 40 };

            btnInstall.Click += BtnInstall_Click;
            btnUninstall.Click += BtnUninstall_Click;

            this.Controls.Add(lblStatus);
            this.Controls.Add(progressBar);
            this.Controls.Add(btnInstall);
            this.Controls.Add(btnUninstall);
            
            lblStatus.Text = "Listo para instalar protección User-Mode avanzada.";
        }

        private void BtnInstall_Click(object sender, EventArgs e)
        {
            btnInstall.Enabled = false;
            btnUninstall.Enabled = false;
            progressBar.Value = 10;

            try
            {
                lblStatus.Text = "Paso 1/3: Creando directorio...";
                if (!Directory.Exists(installDir)) Directory.CreateDirectory(installDir);

                lblStatus.Text = "Paso 2/3: Copiando binarios...";
                File.Copy("CapabilityDenialSystem.exe", Path.Combine(installDir, "CapabilityDenialSystem.exe"), true);
                if (File.Exists("whitelist.json"))
                    File.Copy("whitelist.json", Path.Combine(installDir, "whitelist.json"), true);

                lblStatus.Text = "Paso 3/3: Registrando servicio...";
                string daemonPath = Path.Combine(installDir, "CapabilityDenialSystem.exe");
                RunCommand("sc.exe", $"create {daemonServiceName} binPath= \"{daemonPath} --service\" start= auto DisplayName= \"Capability Denial System Daemon\"");
                RunCommand("sc.exe", $"start {daemonServiceName}");

                progressBar.Value = 100;
                lblStatus.Text = "¡Instalación Exitosa!";
                MessageBox.Show("BastionOps se ha instalado correctamente.\n\nProtecciones activas:\n- Anti-Debugging\n- Anti-Forensics\n- File Integrity Monitoring\n- ETW/WMI Injection Detection\n\nEl sistema está protegido.", "Éxito", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                progressBar.Value = 0;
                lblStatus.Text = "Error durante la instalación.";
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                btnInstall.Enabled = true;
                btnUninstall.Enabled = true;
            }
        }

        private void BtnUninstall_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show("¿Estás seguro de desinstalar BastionOps?", "Confirmar", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
            {
                try
                {
                    RunCommand("sc.exe", $"stop {daemonServiceName}");
                    RunCommand("sc.exe", $"delete {daemonServiceName}");
                    
                    if (Directory.Exists(installDir)) Directory.Delete(installDir, true);
                    
                    MessageBox.Show("Desinstalación completada.", "Éxito", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error al desinstalar: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void RunCommand(string fileName, string arguments)
        {
            var process = Process.Start(new ProcessStartInfo(fileName, arguments)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });
            process.WaitForExit();
        }
    }
}
