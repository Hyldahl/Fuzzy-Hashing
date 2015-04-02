# Fuzzy-Hashing
Library for calculating context triggered piecewise hashes (CTPH) also called fuzzy hashes.

Fuzzy hashes can be used to match data that have similarities, such as two sets of data with sequences of identical bytes in the same order, although bytes in between these sequences may be different in both content and length.

More information about CTPH: [Identifying almost identical files using context triggered piecewise hashes] (http://dfrws.org/2006/proceedings/12-Kornblum.pdf)

## Contents

SpamSum:
A pure .NET managed version of the fuzzy hashing algorithm used in the program [ssdeep] (http://ssdeep.sourceforge.net/) which is based on the spam-email detector [SpamSum] (http://www.samba.org/ftp/unpacked/junkcode/spamsum/) originally developed by Dr. Andrew Trigdell .

## Example of use

```csharp
using System;
using Hyldahl.Hashing.SpamSum;

namespace Hyldahl.Hashing.Test
{
    class SpamSumTest
    {
        public void Test()
        {
            SpamSumSignature signature = FuzzyHashing.Calculate(@"c:\myfile.txt");

            SpamSumSignature signatureToCompare = new SpamSumSignature("768:asdfmAAjaHx/4DpIXYSEAdP0Pn0nxqgeFjviVHeFc:asdftSin0nrelviNeK");

            int result = FuzzyHashing.Compare(signature, signatureToCompare);

            Console.WriteLine("signature:          " + signature);
            Console.WriteLine("signatureToCompare: " + signatureToCompare);
            Console.WriteLine("Similarity:         " + result);
        }
    }
}
```

**Output:**

```
signature:          768:ZoLymAAjaHx/4DpIXYSEAdP0Pn0nxqgeFjviVHeFc:KCHOtSin0nrelviNeK
signatureToCompare: 768:asdfmAAjaHx/4DpIXYSEAdP0Pn0nxqgeFjviVHeFc:asdftSin0nrelviNeK
Similarity:         99
```

