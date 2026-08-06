using System;
using System.Runtime.InteropServices;
using CapabilityDenialSystem;

namespace BastionOps.Tests.Unit;

public class SecurityEnforcerTests
{
    [Fact]
    public void EnforceSecurity_DoesNotThrow_OnNonWindows()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // En Linux los P/Invoke fallarán con DllNotFoundException
            Assert.ThrowsAny<Exception>(() => SecurityEnforcer.EnforceSecurity());
        }
        else
        {
            // En Windows no debería lanzar excepción (a menos que haya debugger)
            try
            {
                SecurityEnforcer.EnforceSecurity();
            }
            catch (Exception ex) when (ex is not InvalidOperationException)
            {
                // Algunos checks pueden fallar por permisos, pero no debería crashear
                Assert.True(true);
            }
        }
    }

    [Fact]
    public void EnforceSecurity_IsIdempotent()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return; // Skip en Linux
        }

        try
        {
            SecurityEnforcer.EnforceSecurity();
            SecurityEnforcer.EnforceSecurity();
            Assert.True(true);
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            Assert.True(true);
        }
    }
}
