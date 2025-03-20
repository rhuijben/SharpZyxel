namespace SharpZyxel;

internal static class Extensions
{
    internal static byte[] AlignUp(this byte[] bytes, int mask = 4)
    {
        if ((bytes.Length & (mask - 1)) == 0)
            return bytes;
        else
        {
            var newLen = bytes.Length - bytes.Length % mask + mask;

            return bytes.PadLeft(newLen);
        }
    }

    internal static byte[] PadLeft(this byte[] bytes, int length)
    {
        if (bytes.Length >= length)
            return bytes;
        else
        {
            byte[] newBytes = new byte[length];

            bytes.AsSpan().CopyTo(newBytes.AsSpan(length - bytes.Length));

            return newBytes;
        }
    }
}
