USE master;
GO

-- enable clr
sp_configure 'clr enabled', 1;
RECONFIGURE;


---- Drop the existing assemblies if they exist
--IF EXISTS (SELECT * FROM sys.assemblies WHERE name = 'HashBytesLibrary')
--    DROP ASSEMBLY HashBytesLibrary;
--GO

DECLARE @HashBytesLibraryHash VARBINARY(64);

-- Replace [your_hash_here] with the actual SHA512 hash value for HashBytes1.dll
SET @HashBytesLibraryHash = CONVERT(VARBINARY(64), 0x2bc2451cc7fb51865b5869de8b1c0c7bc3d75ca304c17f5767e931be1c8e9111cbfec9d3629a1c3300f3ab99f7561a3070daaf211a10863ad9978489ea917436);

-- Add the trusted assembly for HashBytesLibrary
EXEC sp_add_trusted_assembly @hash = @HashBytesLibraryHash, @description = N'HashBytesLibrary';
GO


USE Test;
GO

-- Create the assembly with UNSAFE permission
CREATE ASSEMBLY HashBytesLibrary
FROM 'E:\DBCLR\xhashbytes\HashBytes1.dll'
WITH PERMISSION_SET = UNSAFE;
GO


CREATE FUNCTION dbo.XHASHBYTES (@algorithm NVARCHAR(50), @input VARBINARY(MAX))
RETURNS VARBINARY(MAX)
AS EXTERNAL NAME HashBytesLibrary.XHASHBYTES.ComputeHash;
GO


-- Example of hashing a string using SHA-256
SELECT dbo.XHASHBYTES('SHA-256', CAST('Test input' AS VARBINARY(MAX))) AS SHA256Hash;

-- Example of hashing a string using MD5
SELECT dbo.XHASHBYTES('MD5', CAST('Test input' AS VARBINARY(MAX))) AS MD5Hash;

-- Example of hashing a string using SHA-512
SELECT dbo.XHASHBYTES('SHA-512', CAST('Test input' AS VARBINARY(MAX))) AS SHA512Hash;

-- Example of hashing a string using SHA3-256
SELECT dbo.XHASHBYTES('SHA3-256', CAST('Test input' AS VARBINARY(MAX))) AS SHA3_256Hash;
