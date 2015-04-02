/*****************************************************************************
 * Hyldahl.Hashing                                 Created by: MSH 2010.11.16
 * --------------------------------------------------------------------------
 * FileName: SpamSum\FuzzyHashing.cs
 * --------------------------------------------------------------------------
 * Copyright 2010 Martin Sixhøj Hyldahl
 *****************************************************************************/

/*
  Adapted from ssdeep and spamsum
   
  Spamsum license

  this is a checksum routine that is specifically designed for spam. 
  Copyright Andrew Tridgell <tridge@samba.org> 2002
 
  This code is released under the GNU General Public License version 2
  or later.  Alteratively, you may also use this code under the terms
  of the Perl Artistic license.
 
  If you wish to distribute this code under the terms of a different
  free software license then please ask me. If there is a good reason
  then I will probably say yes.

  http://www.samba.org/ftp/unpacked/junkcode/spamsum/
  
  ssdeep
  http://ssdeep.sourceforge.net/

 */

using System;
using System.IO;
using System.Text;

namespace Hyldahl.Hashing.SpamSum
{
    public class FuzzyHashing
    {
        /*****************************************************
         * FIELDS
         *****************************************************/

        /// Length of an individual fuzzy hash signature component
        private const int SPAMSUM_LENGTH        = 64;

        /// The longest possible length for a fuzzy hash signature (without the filename)
        private const int FUZZY_MAX_RESULT      = (SPAMSUM_LENGTH + (SPAMSUM_LENGTH/2 + 20));

        private const int MIN_BLOCKSIZE   = 3;
        private const int ROLLING_WINDOW  = 7;

        private const int HASH_PRIME     = 0x01000193;
        private const int HASH_INIT      = 0x28021967;

        // Our input buffer when reading files to hash
        private const int BUFFER_SIZE  = 8192;

        private const string b64String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        private static readonly byte[] b64;

        /*****************************************************
         * CONSTRUCTOR
         *****************************************************/

        /// <summary>
        /// Initializes the <see cref="FuzzyHashing"/> class.
        /// </summary>
        static FuzzyHashing()
        {
            b64 = Encoding.ASCII.GetBytes(b64String);
        }

        /*****************************************************
         * HASH METHODS
         *****************************************************/

        /// <summary>
        /// a rolling hash, based on the Adler checksum. By using a rolling hash
        /// we can perform auto resynchronisation after inserts/deletes
        /// 
        /// internally, h1 is the sum of the bytes in the window and h2
        /// is the sum of the bytes times the index
        /// 
        /// h3 is a shift/xor based rolling hash, and is mostly needed to ensure that
        /// we can cope with large blocksize values
        /// </summary>
        /// <param name="c">The c.</param>
        /// <returns>Hash value</returns>
        private static uint roll_hash(RollingState roll_state, byte c)
        {
            roll_state.h2 -= roll_state.h1;
            roll_state.h2 += (uint) ROLLING_WINDOW*c;

            roll_state.h1 += c;
            roll_state.h1 -= roll_state.window[roll_state.n%ROLLING_WINDOW];

            roll_state.window[roll_state.n%ROLLING_WINDOW] = c;
            roll_state.n++;

            /* The original spamsum AND'ed this value with 0xFFFFFFFF which
               in theory should have no effect. This AND has been removed 
               for performance (jk) */
            roll_state.h3 = (roll_state.h3 << 5); //& 0xFFFFFFFF;
            roll_state.h3 ^= c;

            return roll_state.h1 + roll_state.h2 + roll_state.h3;
        }

        /// <summary>
        /// Reset the state of the rolling hash and return the initial rolling hash value
        /// </summary>
        /// <returns>Hash value</returns>
        private static uint roll_reset(out RollingState roll_state)
        {
            roll_state = new RollingState();
            return 0;
        }

        /// <summary>
        /// a simple non-rolling hash, based on the FNV hash
        /// </summary>
        /// <param name="c">The c.</param>
        /// <param name="h">The h.</param>
        /// <returns>Hash value</returns>
        private static uint sum_hash(byte c, uint h)
        {
            h *= HASH_PRIME;
            h ^= c;
            return h;
        }

        /// <summary>
        /// Initializes the specified <paramref name="ctx">SpamSumContext</paramref>
        /// </summary>
        /// <param name="ctx">The SpamSum context.</param>
        /// <param name="stream">The stream.</param>
        /// <returns></returns>
        private static void ss_init(SpamSumContext ctx, Stream stream)
        {
            if (null == ctx)
                throw new ArgumentNullException("ctx");

            // ctx.ret = new byte[FUZZY_MAX_RESULT];

            if (stream != null)
                ctx.total_chars = (uint)stream.Length; // find_file_size(handle);

            ctx.block_size = MIN_BLOCKSIZE;

            while (ctx.block_size * SPAMSUM_LENGTH < ctx.total_chars)
            {
                ctx.block_size = ctx.block_size * 2;
            }
        }

        private static void ss_engine(SpamSumContext ctx, byte[] buffer, uint buffer_size)
        {
            uint i;

            if (null == ctx || null == buffer)
                return;

            for (i = 0; i < buffer_size; ++i)
            {
                /* 
                   at each character we update the rolling hash and
                   the normal hash. When the rolling hash hits the
                   reset value then we emit the normal hash as a
                   element of the signature and reset both hashes
                */
                ctx.h = roll_hash(ctx.roll_state, buffer[i]);
                ctx.h2 = sum_hash(buffer[i], ctx.h2);
                ctx.h3 = sum_hash(buffer[i], ctx.h3);

                if (ctx.h % ctx.block_size == (ctx.block_size - 1))
                {
                    /* we have hit a reset point. We now emit a
                   hash which is based on all chacaters in the
                   piece of the message between the last reset
                   point and this one */
                    ctx.p[ctx.j] = b64[(int) (ctx.h2%64)];
                    if (ctx.j < SPAMSUM_LENGTH - 1)
                    {
                        /* we can have a problem with the tail
                           overflowing. The easiest way to
                           cope with this is to only reset the
                           second hash if we have room for
                           more characters in our
                           signature. This has the effect of
                           combining the last few pieces of
                           the message into a single piece */

                        ctx.h2 = HASH_INIT;
                        (ctx.j)++;
                    }
                }

                /* this produces a second signature with a block size
                   of block_size*2. By producing dual signatures in
                   this way the effect of small changes in the message
                   size near a block size boundary is greatly reduced. */
                if (ctx.h % (ctx.block_size*2) == ((ctx.block_size*2) - 1))
                {
                    ctx.ret2[ctx.k] = b64[(int) (ctx.h3%64)];
                    if (ctx.k < SPAMSUM_LENGTH/2 - 1)
                    {
                        ctx.h3 = HASH_INIT;
                        (ctx.k)++;
                    }
                }
            }
        }

        private static int ss_update(SpamSumContext ctx, Stream stream)
        {
            int bytes_read;
            byte[] buffer;

            if (null == ctx || null == stream)
                return 1;

            buffer = new byte[BUFFER_SIZE];

            //snprintf(ctx->ret, 12, "%u:", ctx->block_size);
            //ctx.ret = Encoding.ASCII.GetBytes(string.Format("{0}:", ctx.block_size));

            //ctx.p = ctx.ret + strlen(ctx.ret);

            //memset(ctx->p, 0, SPAMSUM_LENGTH+1);
            //memset(ctx->ret2, 0, sizeof(ctx->ret2));

            ctx.p = new byte[SPAMSUM_LENGTH + 1];
            ctx.ret2 = new byte[SPAMSUM_LENGTH/2 + 1];

            ctx.k = ctx.j = 0;
            ctx.h3 = ctx.h2 = HASH_INIT;
            ctx.h = roll_reset(out ctx.roll_state);

            while ((bytes_read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                ss_engine(ctx, buffer, (uint) bytes_read);
            }

            if (ctx.h != 0)
            {
                ctx.p[ctx.j] = b64[(int) (ctx.h2%64)];
                ctx.ret2[ctx.k] = b64[(int) (ctx.h3%64)];
            }

            //strcat(ctx.p + ctx.j, ":");
            //strcat(ctx.p + ctx.j, ctx.ret2);

            //ctx.p[ctx.j] = Encoding.ASCII.GetBytes(":")[0];
            //Copy(ctx.ret2, 0, ctx.p, ctx.j + 1, ctx.ret2.Length);

            //byte[] result = new byte[FUZZY_MAX_RESULT];
            //uint resultIdx = (uint)Copy(ctx.ret, 0, result, 0, ctx.ret.Length);
            //Copy(ctx.p, 0, result, resultIdx, ctx.p.Length);

            //ctx.ret = result;

            ctx.signature = new SpamSumSignature(ctx.block_size, GetArray(ctx.p, (int)ctx.j + 1), GetArray(ctx.ret2, (int)ctx.k + 1));

            return 0;
        }

        private static byte[] GetArray(byte[] input, int maxLength)
        {
            if (input.Length == maxLength)
                return input;

            byte[] output = new byte[maxLength];

            Copy(input, 0, output, 0, maxLength);

            return output;
        }

        private static int Copy(byte[] source, uint sourceIdx, byte[] destination, uint destinationIdx, int maxLength)
        {
            for (int idx = 0; idx < maxLength; idx++)
            {
                if (sourceIdx + idx >= source.Length)
                    return idx;

                if (source[sourceIdx + idx] == 0)
                    return idx;

                destination[destinationIdx + idx] = source[sourceIdx + idx];
            }

            return maxLength;
        }

        /// <summary>
        /// /// Calculates the SpamSum hash for specified <paramref name="stream"/>.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <returns>SpamSum signature</returns>
        public static SpamSumSignature Calculate(Stream stream)
        {
            if (null == stream)
                throw new ArgumentNullException("stream");

            bool done = false;

            SpamSumContext ctx = new SpamSumContext();

            long filepos = stream.Position;

            ss_init(ctx, stream);

            while (!done)
            {
                stream.Seek(0, SeekOrigin.Begin);

                ss_update(ctx, stream);

                // our blocksize guess may have been way off - repeat if necessary
                if (ctx.block_size > MIN_BLOCKSIZE && ctx.j < SPAMSUM_LENGTH / 2)
                    ctx.block_size = ctx.block_size / 2;
                else
                    done = true;
            }

            //strncpy(result, ctx.ret, FUZZY_MAX_RESULT);
            //byte[] result = new byte[FUZZY_MAX_RESULT];
            //Copy(ctx.ret, 0, result, 0, FUZZY_MAX_RESULT);

            stream.Position = filepos;

            return ctx.signature;
        }

        /// <summary>
        /// /// Calculates the SpamSum hash for specified <paramref name="filename"/>.
        /// </summary>
        /// <param name="filename">The filename.</param>
        /// <returns>SpamSum signature</returns>
        public static SpamSumSignature Calculate(string filename)
        {
            if (null == filename)
                throw new ArgumentNullException(filename);

            using (Stream stream = File.OpenRead(filename))
            {
                return Calculate(stream);
            }
        }

        /*****************************************************
         * HASH COMPARISSON METHODS
         *****************************************************/

        /// <summary>
        /// we only accept a match if we have at least one common substring in
        /// the signature of length ROLLING_WINDOW. This dramatically drops the
        /// false positive rate for low score thresholds while having
        /// negligable affect on the rate of spam detection.
        /// 
        /// return 1 if the two strings do have a common substring, 0 otherwise
        /// </summary>
        /// <param name="s1">The s1.</param>
        /// <param name="s2">The s2.</param>
        /// <returns></returns>
        private static int has_common_substring(byte[] s1, byte[] s2)
        {
            int i, j;
            int num_hashes;
            uint[] hashes = new uint[SPAMSUM_LENGTH];

            /* there are many possible algorithms for common substring
               detection. In this case I am re-using the rolling hash code
               to act as a filter for possible substring matches */

            RollingState roll_state;
            roll_reset(out roll_state);

            /* first compute the windowed rolling hash at each offset in
               the first string */
            for (i = 0; i < s1.Length; i++)
            {
                hashes[i] = roll_hash(roll_state, s1[i]);
            }
            num_hashes = i;

            roll_reset(out roll_state);

            /* now for each offset in the second string compute the
               rolling hash and compare it to all of the rolling hashes
               for the first string. If one matches then we have a
               candidate substring match. We then confirm that match with
               a direct string comparison */
            for (i = 0; i < s2.Length; i++)
            {
                uint h = roll_hash(roll_state, s2[i]);
                if (i < ROLLING_WINDOW - 1) continue;
                for (j = ROLLING_WINDOW - 1; j < num_hashes; j++)
                {
                    if (hashes[j] != 0 && hashes[j] == h)
                    {
                        /* we have a potential match - confirm it */
                        //if (strlen(s2 + i - (ROLLING_WINDOW - 1)) >= ROLLING_WINDOW &&
                        //    strncmp(s2 + i - (ROLLING_WINDOW - 1),
                        //            s1 + j - (ROLLING_WINDOW - 1),
                        //            ROLLING_WINDOW) == 0)
                        if ((s2.Length - i - (ROLLING_WINDOW - 1)) >= ROLLING_WINDOW &&
                            ArrayCompare(s2, 
                                         (s2.Length - i - (ROLLING_WINDOW - 1)),
                                         s1,
                                         (s1.Length - j - (ROLLING_WINDOW - 1)),
                                         ROLLING_WINDOW) == 0)
                        {
                            return 1;
                        }
                    }
                }
            }

            return 0;
        }

        private static int ArrayCompare(byte[] array1, int idx1, byte[] array2, int idx2, int rollingWindow)
        {
            bool result = true;

            for (int a = 0; a < rollingWindow; a++)
            {
                if ((a + idx1) > array1.Length)
                    return 1;

                if ((a + idx2) > array2.Length)
                    return 2;

                result &= array1[a + idx1] == array2[a + idx2];

                if (!result)
                    return -1;
            }

            return 0;
        }

        /// <summary>
        /// eliminate sequences of longer than 3 identical characters. These
        /// sequences contain very little information so they tend to just bias
        /// the result unfairly
        /// </summary>
        /// <param name="str">The STR.</param>
        /// <returns></returns>
        private static byte[] eliminate_sequences(byte[] str)
        {
            byte[] ret;
            int i, j, len;

            ret = (byte[]) str.Clone();

            len = str.Length;

            for (i = j = 3; i < len; i++)
            {
                if (str[i] != str[i - 1] ||
                    str[i] != str[i - 2] ||
                    str[i] != str[i - 3])
                {
                    ret[j++] = str[i];
                }
            }

            ret[j] = 0;

            return ret;
        }

        private static byte[] eliminate_sequences2(byte[] str)
        {
            byte[] ret;
            int i, j, len;

            len = str.Length;

            ret = new byte[len];

            for (i = j = 3; i < len; i++)
            {
                if (str[i] != str[i - 1] ||
                    str[i] != str[i - 2] ||
                    str[i] != str[i - 3])
                {
                    ret[j++] = str[i];
                }
            }

            return ret;
        }

        /// <summary>
        /// this is the low level string scoring algorithm. It takes two strings
        /// and scores them on a scale of 0-100 where 0 is a terrible match and
        /// 100 is a great match. The block_size is used to cope with very small
        /// messages.
        /// </summary>
        private static uint score_strings(byte[] s1, byte[] s2, uint block_size)
        {
            uint score;
            uint len1, len2;
            //int edit_distn(const char *from, int from_len, const char *to, int to_len);

            len1 = (uint)s1.Length;
            len2 = (uint)s2.Length;

            if (len1 > SPAMSUM_LENGTH || len2 > SPAMSUM_LENGTH)
            {
                /* not a real spamsum signature? */
                return 0;
            }

            /* the two strings must have a common substring of length
               ROLLING_WINDOW to be candidates */
            if (has_common_substring(s1, s2) == 0)
            {
                return 0;
            }

            /* compute the edit distance between the two strings. The edit distance gives
               us a pretty good idea of how closely related the two strings are */
            score = edit_distn(s1, len1, s2, len2);

            /* scale the edit distance by the lengths of the two
               strings. This changes the score to be a measure of the
               proportion of the message that has changed rather than an
               absolute quantity. It also copes with the variability of
               the string lengths. */
            score = (score*SPAMSUM_LENGTH)/(len1 + len2);

            /* at this stage the score occurs roughly on a 0-64 scale,
             * with 0 being a good match and 64 being a complete
             * mismatch */

            /* rescale to a 0-100 scale (friendlier to humans) */
            score = (100*score)/64;

            /* it is possible to get a score above 100 here, but it is a
               really terrible match */
            if (score >= 100) return 0;

            /* now re-scale on a 0-100 scale with 0 being a poor match and
               100 being a excellent match. */
            score = 100 - score;

            //  printf ("len1: %"PRIu32"  len2: %"PRIu32"\n", len1, len2);

            /* when the blocksize is small we don't want to exaggerate the match size */
            if (score > block_size/MIN_BLOCKSIZE*System.Math.Min(len1, len2))
            {
                score = block_size/MIN_BLOCKSIZE*System.Math.Min(len1, len2);
            }
            return score;
        }

        private static uint edit_distn(byte[] s1, uint len1, byte[] s2, uint len2)
        {
            return (uint)EditDistance.edit_distn(s1, (int)len1, s2, (int)len2);
        }

        /// <summary>
        /// given two spamsum signature return a value indicating the degree to which they match.
        /// </summary>
        /// <param name="signature1">The first signature.</param>
        /// <param name="signature2">The second signature.</param>
        /// <returns></returns>
        public static int Compare(SpamSumSignature signature1, SpamSumSignature signature2)
        {
            uint block_size1, block_size2;
            uint score = 0;
            byte[] s1, s2;
            byte[] s1_1, s1_2;
            byte[] s2_1, s2_2;

            if (null == signature1 || null == signature2)
                return -1;

            //string str1, str2;
            //int str1Idx, str2Idx;

            //str1 = Encoding.ASCII.GetString(bytes1);
            //str2 = Encoding.ASCII.GetString(bytes2);

            //// each spamsum is prefixed by its block size
            //if (sscanf(str1, "%u:", &block_size1) != 1 ||
            //    sscanf(str2, "%u:", &block_size2) != 1) {
            //  return -1;
            //}

            //str1Idx = str1.IndexOf(':');
            //str2Idx = str1.IndexOf(':');

            //block_size1 = uint.Parse(str1.Substring(0, str1Idx));
            //block_size2 = uint.Parse(str2.Substring(0, str2Idx));
            block_size1 = signature1.BlockSize;
            block_size2 = signature2.BlockSize;

            // if the blocksizes don't match then we are comparing
            // apples to oranges. This isn't an 'error' per se. We could
            // have two valid signatures, but they can't be compared. 
            if (block_size1 != block_size2 &&
                block_size1 != block_size2*2 &&
                block_size2 != block_size1*2)
            {
                return 0;
            }

            // move past the prefix
            //str1Idx++;
            //str2Idx++;

            //if (str1Idx >= str1.Length || str2Idx >= str2.Length)
            //{
            //    // badly formed ... 
            //    return -1;
            //}

            // there is very little information content is sequences of
            // the same character like 'LLLLL'. Eliminate any sequences
            // longer than 3. This is especially important when combined
            // with the has_common_substring() test below. 
            //s1 = eliminate_sequences(Encoding.ASCII.GetBytes(str1.Substring(str1Idx)));
            //s2 = eliminate_sequences(Encoding.ASCII.GetBytes(str2.Substring(str2Idx)));
            s1 = eliminate_sequences2(signature1.HashPart1);
            s2 = eliminate_sequences2(signature2.HashPart1);

            //if (!s1 || !s2) return 0;

            // now break them into the two pieces 
            s1_1 = s1;
            s2_1 = s2;

            //s1_2 = strchr(s1, ':');
            //s2_2 = strchr(s2, ':');
            //string s1_2_str = Encoding.ASCII.GetString(s1);
            //string s2_2_str = Encoding.ASCII.GetString(s2);

            //s1_2 = Encoding.ASCII.GetBytes(s1_2_str.Substring(s1_2_str.IndexOf(':') + 1));
            //s2_2 = Encoding.ASCII.GetBytes(s2_2_str.Substring(s2_2_str.IndexOf(':') + 1));
            s1_2 = eliminate_sequences2(signature1.HashPart2);
            s2_2 = eliminate_sequences2(signature2.HashPart2);

            //if (!s1_2 || !s2_2) {
            //  // a signature is malformed - it doesn't have 2 parts 
            //  return 0;
            //}

            //*s1_2++ = 0;
            //*s2_2++ = 0;

            // each signature has a string for two block sizes. We now
            // choose how to combine the two block sizes. We checked above
            // that they have at least one block size in common 
            if (block_size1 == block_size2)
            {
                uint score1, score2;
                score1 = score_strings(s1_1, s2_1, block_size1);
                score2 = score_strings(s1_2, s2_2, block_size2);

                //    s->block_size = block_size1;

                score = System.Math.Max(score1, score2);
            }
            else if (block_size1 == block_size2*2)
            {

                score = score_strings(s1_1, s2_2, block_size1);
                //    s->block_size = block_size1;
            }
            else
            {

                score = score_strings(s1_2, s2_1, block_size2);
                //    s->block_size = block_size2;
            }

            return (int) score;
        }

        /*****************************************************
         * INNER TYPES
         *****************************************************/

        private class RollingState
        {
            public byte[] window;
            public uint h1, h2, h3;
            public uint n;

            public RollingState()
            {
                window = new byte[ROLLING_WINDOW];
                h1 = h2 = h3 = n = default(uint);
            }
        }

        private class SpamSumContext
        {
            //public byte ret, p;
            //public byte[] ret, p;
            public byte[] p;
            public uint total_chars;
            public uint h, h2, h3;
            public uint j, n, i, k;
            public uint block_size;
            public byte[] ret2;
            public RollingState roll_state;
            public SpamSumSignature signature; // ret has been replaced with SpamSumSignature

            public SpamSumContext()
            {
                ret2 = new byte[SPAMSUM_LENGTH / 2 + 1];

                //ret = p = default(byte[]);
                p = default(byte[]);
                total_chars = h = h2 = h3 = j = n = i = k = block_size = default(uint);
            }
        }
    }
}
