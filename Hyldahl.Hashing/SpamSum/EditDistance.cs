/*****************************************************************************
 * Hyldahl.Hashing                                 Created by: MSH 2010.11.16
 * --------------------------------------------------------------------------
 * FileName: SpamSum\EditDistance.cs
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

#define TRN_SPEEDUP

namespace Hyldahl.Hashing.SpamSum
{
    public class EditDistance
    {
        /*
          This edit distance code is taken from trn3.6. A few minor
          modifications have been made by Andrew Tridgell <tridge@samba.org>
          for use in spamsum.
        */


        /***************************************************************************/


        /* The authors make no claims as to the fitness or correctness of this software
         * for any use whatsoever, and it is provided as is. Any use of this software
         * is at the user's own risk. 
         */

        /* edit_dist -- returns the minimum edit distance between two strings

            Program by:  Mark Maimone   CMU Computer Science   13 Nov 89
            Last Modified:  28 Jan 90

           If the input strings have length n and m, the algorithm runs in time
           O(nm) and space O(min(m,n)).

        HISTORY
           13 Nov 89 (mwm) Created edit_dist() and set_costs().

           28 Jan 90 (mwm) Added view_costs().  Should verify that THRESHOLD
           computations will work even when THRESHOLD is not a multiple of
           sizeof(int).

           17 May 93 (mwm) Improved performance when used with trn's newsgroup
           processing; assume all costs are 1, and you can terminate when a
           threshold is exceeded.
        */

        private const int MIN_DIST = 100;

        /* Use a less-general version of the
           routine, one that's better for trn.
           All change costs are 1, and it's okay
           to terminate if the edit distance is
           known to exceed MIN_DIST */

        private const int THRESHOLD = 4000;     /* worry about allocating more memory only
                                                   when this # of bytes is exceeded */

        private const int STRLENTHRESHOLD = ((int) ((THRESHOLD / sizeof(int) - 3) / 2));

        // #define SAFE_ASSIGN(x,y) (((x) != NULL) ? (*(x) = (y)) : (y))

        // #define swap_int(x,y)  (_iswap = (x), (x) = (y), (y) = _iswap)
        private static void swap_int(ref int x, ref int y)
        {
            int _iswap = (x);
            (x) = (y);
            (y) = _iswap;
        }

        // #define swap_char(x,y) (_cswap = (x), (x) = (y), (y) = _cswap)
        private static void swap_char(ref byte[] x, ref byte[] y)
        {
            byte[] _cswap = (x);
            (x) = (y);
            (y) = _cswap;
        }

        //#define min3(x,y,z) (_mx = (x), _my = (y), _mz = (z), (_mx < _my ? (_mx < _mz ? _mx : _mz) : (_mz < _my) ? _mz : _my))
        private static int min3(int x, int y, int z)
        {
            int _mx = (x);
            int _my = (y);
            int _mz = (z);
            return (_mx < _my ? (_mx < _mz ? _mx : _mz) : (_mz < _my) ? _mz : _my);
        }

        //#define min2(x,y) (_mx = (x), _my = (y), (_mx < _my ? _mx : _my))
        private static int min2(int x,int y)
        {
            int _mx = (x);
            int _my = (y);
            return (_mx < _my ? _mx : _my);
        }

        static int insert_cost = 1;
        static int delete_cost = 1;
#if(!TRN_SPEEDUP)
        static int change_cost = 1;
        static int swap_cost   = 1;
#endif

        static int  _iswap;             /* swap_int temp variable */
        static char _cswap;             /* swap_char temp variable */
        static int  _mx, _my, _mz;      /* min2, min3 temp variables */

        private delegate int arDelegate(int x, int y, int index);
        private delegate int doubleIntDelegate(int x, int y);
        private delegate int intDelegate(int x);

        /* edit_distn -- returns the edit distance between two strings, or -1 on
           failure */
        public static int edit_distn(byte[] from, int from_len, byte[] to, int to_len) 
        {
#if(!TRN_SPEEDUP)
            int ins, del, ch;           /* local copies of edit costs */
#endif
            int row, col, index = 0;    /* dynamic programming counters */
            int radix;                  /* radix for modular indexing */
#if(TRN_SPEEDUP)
            int low;
#endif
            int[] buffer;               /* pointer to storage for one row
                                           of the d.p. array */

            int[] store = new int[THRESHOLD / sizeof (int)];
                                        /* a small amount of static
                                           storage, to be used when the
                                           input strings are small enough */

            /* Handle trivial cases when one string is empty */

            if (from == null)
                if (to == null)
                    return 0;
                else
                    return to_len * insert_cost;
            else if (to == null)
                return from_len * delete_cost;

            /* Initialize registers */

            radix = 2 * from_len + 3;

#if(TRN_SPEEDUP)
            int ins = 1;
            int del = 1;
            int ch  = 3;
            int swap_cost = 5;
#else
            ins  = insert_cost;
            del  = delete_cost;
            ch   = change_cost;
#endif

            /* Make   from   short enough to fit in the static storage, if it's at all possible */

            if (from_len > to_len && from_len > STRLENTHRESHOLD) 
            {
                swap_int(ref from_len, ref to_len);
                swap_char(ref from, ref to);
#if(!TRN_SPEEDUP)
                swap_int(ref ins, ref del);
#endif
            } /* if from_len > to_len */

            /* Allocate the array storage (from the heap if necessary) */

            if (from_len <= STRLENTHRESHOLD)
                buffer = store;
            else
                buffer = new int[radix];

            /* Here's where the fun begins.  We will find the minimum edit distance
                using dynamic programming.  We only need to store two rows of the matrix
                at a time, since we always progress down the matrix.  For example,
                given the strings "one" and "two", and insert, delete and change costs
                equal to 1:

                    _  o  n  e
                _  0  1  2  3
                t  1  1  2  3
                w  2  2  2  3
                o  3  2  3  3

                The dynamic programming recursion is defined as follows:

                ar(x,0) := x * insert_cost
                ar(0,y) := y * delete_cost
                ar(x,y) := min(a(x - 1, y - 1) + (from[x] == to[y] ? 0 : change),
                            a(x - 1, y) + insert_cost,
                            a(x, y - 1) + delete_cost,
                            a(x - 2, y - 2) + (from[x] == to[y-1] &&
                                    from[x-1] == to[y] ? swap_cost :
                                    infinity))

                Since this only looks at most two rows and three columns back, we need
                only store the values for the two preceeding rows.  In this
                implementation, we do not explicitly store the zero column, so only 2 *
                from_len + 2   words are needed.  However, in the implementation of the
                swap_cost   check, the current matrix value is used as a buffer; we
                can't overwrite the earlier value until the   swap_cost   check has
                been performed.  So we use   2 * from_len + 3   elements in the buffer.
            */

            //#define ar(x,y,index) (((x) == 0) ? (y) * del : (((y) == 0) ? (x) * ins : 
            //    \ buffer[mod(index)]))
            //#define NW(x,y)	  ar(x, y, index + from_len + 2)
            //#define N(x,y)	  ar(x, y, index + from_len + 3)
            //#define W(x,y)	  ar(x, y, index + radix - 1)
            //#define NNWW(x,y) ar(x, y, index + 1)
            //#define mod(x) ((x) % radix)

            intDelegate mod = delegate(int x)
            {
                return (x) % radix;
            };

            arDelegate ar = delegate(int x, int y, int idx)
            {
                return (((x) == 0)
                            ? (y)*del
                            : (((y) == 0)
                                    ? (x)*ins
                                    : buffer[mod(idx)]));
            };

            doubleIntDelegate NW = delegate(int x, int y)
            {
                return ar(x, y, index + from_len + 2);
            };

            doubleIntDelegate N = delegate(int x, int y)
            {
                return ar(x, y, index + from_len + 3);
            };

            doubleIntDelegate W = delegate(int x, int y)
            {
                return ar(x, y, index + radix - 1);
            };

            doubleIntDelegate NNWW = delegate(int x, int y)
            {
                return ar(x, y, index + 1);
            };

            index = 0;

#if(DEBUG_EDITDIST)
            Console.Write("      ");
            for (col = 0; col < from_len; col++)
                Console.Write(" {0} ", from[col]);
            Console.Write("\n   ");

            for (col = 0; col <= from_len; col++)
                Console.Write("{0}", col * del);
#endif

            /* Row 0 is handled implicitly; its value at a given column is   col*del.
               The loop below computes the values for Row 1.  At this point we know the
               strings are nonempty.  We also don't need to consider swap costs in row
               1.

               COMMENT:  the indicies   row and col   below point into the STRING, so
               the corresponding MATRIX indicies are   row+1 and col+1.
            */

            buffer[index++] = min2(ins + del, (from[0] == to[0] ? 0 : ch));
#if(TRN_SPEEDUP)
            low = buffer[mod(index + radix - 1)];
#endif

#if(DEBUG_EDITDIST)
            Console.Write("\n {0} {1} {2} ", to[0], ins, buffer[index - 1]);
#endif

            for (col = 1; col < from_len; col++)
            {
                buffer[index] = min3(
                    col * del + ((from[col] == to[0]) ? 0 : ch),
                    (col + 1) * del + ins,
                    buffer[index - 1] + del);
#if(TRN_SPEEDUP)
                if (buffer[index] < low)
                    low = buffer[index];
#endif
                index++;

#if(DEBUG_EDITDIST)
                Console.Write("{0} ", buffer[index - 1]);
#endif

            } /* for col = 1 */

#if(DEBUG_EDITDIST)
            Console.Write("\n {0} {1} ", to[1], 2 * ins);
#endif

            /* Now handle the rest of the matrix */

            for (row = 1; row < to_len; row++) {
                for (col = 0; col < from_len; col++) {
                    
                    buffer[index] = min3(
                        NW(row, col) + ((from[col] == to[row]) ? 0 : ch),
                        N(row, col + 1) + ins,
                        W(row + 1, col) + del);
                    
                    if (from[col] == to[row - 1] && col > 0 && from[col - 1] == to[row])
                        buffer[index] = min2(buffer[index], NNWW(row - 1, col - 1) + swap_cost);

#if(DEBUG_EDITDIST)
                Console.Write("{0} ", buffer[index]);
#endif
#if(TRN_SPEEDUP)
                if (buffer[index] < low || col == 0)
                    low = buffer[index];
#endif

                index = mod(index + 1);
            } /* for col = 1 */

#if(DEBUG_EDITDIST)
            if (row < to_len - 1)
                Console.Write("\n {0} {1} ", to[row+1], (row + 2) * ins);
            else
                Console.Write("\n");
#endif
#if(TRN_SPEEDUP)
            if (low > MIN_DIST)
                break;
#endif
            } /* for row = 1 */

            row = buffer[mod(index + radix - 1)];
            
            return row;
        } /* edit_distn */
    }
}
