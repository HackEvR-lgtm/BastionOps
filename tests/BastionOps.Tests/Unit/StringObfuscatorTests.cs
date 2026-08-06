using CapabilityDenialSystem;

namespace BastionOps.Tests.Unit;

public class StringObfuscatorTests
{
    [Theory]
    [InlineData("test")]
    [InlineData("BastionOps")]
    [InlineData("SensitiveData123!@#")]
    [InlineData("")]
    [InlineData("a")]
    public void EncodeDecode_RoundTrip_ReturnsOriginal(string original)
    {
        string encoded = StringObfuscator.Encode(original);
        string decoded = StringObfuscator.Decode(encoded);

        Assert.Equal(original, decoded);
    }

    [Fact]
    public void Encode_ProducesDifferentOutput()
    {
        string original = "password123";

        string encoded = StringObfuscator.Encode(original);

        Assert.NotEqual(original, encoded);
        Assert.NotEmpty(encoded);
    }

    [Fact]
    public void Encode_DifferentInputs_ProduceDifferentOutputs()
    {
        string encoded1 = StringObfuscator.Encode("input1");
        string encoded2 = StringObfuscator.Encode("input2");

        Assert.NotEqual(encoded1, encoded2);
    }

    [Fact]
    public void Decode_WithInvalidBase64_ReturnsInputUnchanged()
    {
        string invalid = "!!!not-valid-base64!!!";

        string result = StringObfuscator.Decode(invalid);

        Assert.Equal(invalid, result);
    }

    [Fact]
    public void SecureClear_WithValidArray_ZerosData()
    {
        byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };

        StringObfuscator.SecureClear(data);

        Assert.All(data, b => Assert.Equal(0, b));
    }

    [Fact]
    public void SecureClear_WithNull_DoesNotThrow()
    {
        StringObfuscator.SecureClear(null!);
    }

    [Fact]
    public void SecureClear_WithLargeArray_ZerosAllData()
    {
        byte[] data = new byte[1024];
        new Random().NextBytes(data);

        StringObfuscator.SecureClear(data);

        Assert.All(data, b => Assert.Equal(0, b));
    }

    [Fact]
    public void EncodeDecode_SpecialCharacters_PreservesData()
    {
        string original = "\n\r\t\0\x01\xFF";

        string encoded = StringObfuscator.Encode(original);
        string decoded = StringObfuscator.Decode(encoded);

        Assert.Equal(original, decoded);
    }
}
