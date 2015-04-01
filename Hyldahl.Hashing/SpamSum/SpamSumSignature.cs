/*****************************************************************************
 * Hyldahl.Hashing                                 Created by: MSH 2010.11.16
 * --------------------------------------------------------------------------
 * FileName: SpamSum\SpamSumSignature.cs
 * --------------------------------------------------------------------------
 * Copyright 2010 Martin Sixhøj Hyldahl
 *****************************************************************************/

using System;
using System.Text;

namespace Hyldahl.Hashing.SpamSum
{
    public sealed class SpamSumSignature : IEquatable<SpamSumSignature>
    {
        /*****************************************************
         * FIELDS
         *****************************************************/
        private uint blockSize;
        private byte[] hash1;
        private byte[] hash2;

        /*****************************************************
         * CONSTRUCTOR
         *****************************************************/

        /// <summary>
        /// Initializes a new instance of the <see cref="SpamSumSignature"/> class.
        /// </summary>
        /// <param name="signature">The signature.</param>
        public SpamSumSignature(string signature)
        {
            if (string.IsNullOrEmpty(signature))
                throw new ArgumentException("Signature string cannot be null or empty.", "signature");

            int idx1 = signature.IndexOf(':');
            int idx2 = signature.IndexOf(':', idx1 + 1);

            if (idx1 < 0)
                throw new ArgumentException("Signature is not valid.", "signature");

            if (idx2 < 0)
                throw new ArgumentException("Signature is not valid.", "signature");

            blockSize   = uint.Parse(signature.Substring(0, idx1));
            hash1       = Encoding.ASCII.GetBytes(signature.Substring(idx1 + 1, idx2 - idx1 - 1));
            hash2       = Encoding.ASCII.GetBytes(signature.Substring(idx2 + 1));
        }

        public SpamSumSignature(uint blockSize, byte[] hash1, byte[] hash2)
        {
            this.blockSize  = blockSize;
            this.hash1      = hash1;
            this.hash2      = hash2;
        }

        /*****************************************************
         * OPERATORS
         *****************************************************/

        /// <summary>
        /// Performs an implicit conversion from <see cref="System.String"/> to <see cref="SpamSumSignature"/>.
        /// </summary>
        /// <param name="signature">The signature.</param>
        /// <returns>The result of the conversion.</returns>
        public static implicit operator SpamSumSignature(string signature)
        {
            return new SpamSumSignature(signature);
        }

        /*****************************************************
         * METHODS
         *****************************************************/

        public override bool Equals(object obj)
        {
            if (!(obj is SpamSumSignature))
                return false;

            return this.Equals((SpamSumSignature)obj);
        }

        public bool Equals(SpamSumSignature other)
        {
            if (object.ReferenceEquals(this, other))
                return true;

            if (this.blockSize != other.blockSize)
                return false;

            if (this.hash1.Length != other.hash1.Length)
                return false;

            if (this.hash2.Length != other.hash2.Length)
                return false;

            for (int idx = 0; idx < hash1.Length; idx++)
            {
                if (this.hash1[idx] != other.hash1[idx])
                    return false;
            }

            for (int idx = 0; idx < hash2.Length; idx++)
            {
                if (this.hash2[idx] != other.hash2[idx])
                    return false;
            }

            return true;
        }

        public override string ToString()
        {
            string hashText1 = Encoding.ASCII.GetString(hash1);
            string hashText2 = Encoding.ASCII.GetString(hash2);
            return string.Format("{0}:{1}:{2}", blockSize, hashText1, hashText2);
        }

        /*****************************************************
         * PROPERTIES
         *****************************************************/

        /// <summary>
        /// Gets the size of the block.
        /// </summary>
        /// <value>The size of the block.</value>
        public uint BlockSize
        {
            get { return blockSize; }
        }

        /// <summary>
        /// Gets the first hash part.
        /// </summary>
        /// <value>The first hash part.</value>
        public byte[] HashPart1
        {
            get { return hash1; }
        }

        /// <summary>
        /// Gets the second hash part.
        /// </summary>
        /// <value>The second hash part.</value>
        public byte[] HashPart2
        {
            get { return hash2; }
        }
    }
}
