using System;
using System.IO;
using System.Text;
using CapabilityDenialSystem;

namespace BastionOps.Tests.Unit;

public class HashUtilityTests : IDisposable
{
    private readonly string _testFilePath;

    public HashUtilityTests()
    {
        _testFilePath = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.txt");
    }

    public void Dispose()
    {
        try { File.Delete(_testFilePath); } catch { }
    }

    [Fact]
    public void ComputeSha256_WithValidFile_ReturnsCorrectHash()
    {
        string content = "BastionOps Test Content";
        File.WriteAllText(_testFilePath, content);
        string expectedHash = ComputeExpectedSha256(content);

        string actualHash = HashUtility.ComputeSha256(_testFilePath);

        Assert.Equal(expectedHash, actualHash);
    }

    [Fact]
    public void ComputeSha256_WithNonExistentFile_ReturnsEmptyString()
    {
        string result = HashUtility.ComputeSha256(@"C:\NonExistent\File.exe");

        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void VerifyFileHash_WithMatchingHash_ReturnsTrue()
    {
        string content = "Test for hash verification";
        File.WriteAllText(_testFilePath, content);
        string hash = HashUtility.ComputeSha256(_testFilePath);

        bool result = HashUtility.VerifyFileHash(_testFilePath, hash);

        Assert.True(result);
    }

    [Fact]
    public void VerifyFileHash_WithNonMatchingHash_ReturnsFalse()
    {
        File.WriteAllText(_testFilePath, "Original content");

        bool result = HashUtility.VerifyFileHash(_testFilePath, "0000000000000000000000000000000000000000000000000000000000000000");

        Assert.False(result);
    }

    [Fact]
    public void VerifyFileHash_WithNullPath_ReturnsFalse()
    {
        bool result = HashUtility.VerifyFileHash(null!, "somehash");

        Assert.False(result);
    }

    [Fact]
    public void VerifyFileHash_WithNullHash_ReturnsFalse()
    {
        bool result = HashUtility.VerifyFileHash(_testFilePath, null!);

        Assert.False(result);
    }

    [Fact]
    public void ComputeSha256_WithEmptyFile_ReturnsValidHash()
    {
        File.WriteAllText(_testFilePath, "");

        string result = HashUtility.ComputeSha256(_testFilePath);

        Assert.NotNull(result);
        Assert.Equal(64, result.Length);
    }

    private static string ComputeExpectedSha256(string content)
    {
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        byte[] bytes = Encoding.UTF8.GetBytes(content);
        byte[] hash = sha256.ComputeHash(bytes);
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }
}
