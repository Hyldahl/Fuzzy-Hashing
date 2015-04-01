/*****************************************************************************
 * Hyldahl.Hashing.Test                            Created by: MSH 2010.11.16
 * --------------------------------------------------------------------------
 * FileName: FuzzyHashingTest.cs
 * --------------------------------------------------------------------------
 * Copyright 2010 Martin Sixhøj Hyldahl
 *****************************************************************************/

using Hyldahl.Hashing.SpamSum;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;

namespace Hyldahl.Hashing.Test
{
    /// <summary>
    ///This is a test class for FuzzyHashingTest and is intended
    ///to contain all FuzzyHashingTest Unit Tests
    ///</summary>
    [TestClass()]
    public class FuzzyHashingTest
    {
        private TestContext testContextInstance;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextInstance;
            }
            set
            {
                testContextInstance = value;
            }
        }

        #region Additional test attributes
        // 
        //You can use the following additional attributes as you write your tests:
        //
        //Use ClassInitialize to run code before running the first test in the class
        //[ClassInitialize()]
        //public static void MyClassInitialize(TestContext testContext)
        //{
        //}
        //
        //Use ClassCleanup to run code after all tests in a class have run
        //[ClassCleanup()]
        //public static void MyClassCleanup()
        //{
        //}
        //
        //Use TestInitialize to run code before running each test
        //[TestInitialize()]
        //public void MyTestInitialize()
        //{
        //}
        //
        //Use TestCleanup to run code after each test has run
        //[TestCleanup()]
        //public void MyTestCleanup()
        //{
        //}
        //
        #endregion


        public void Test()
        {
            SpamSumSignature signature = FuzzyHashing.Calculate(@"G:\ssdeep-2.6\ssdeep-2.6\ssdeep.exe");

            SpamSumSignature signatureToCompare = new SpamSumSignature("768:asdfmAAjaHx/4DpIXYSEAdP0Pn0nxqgeFjviVHeFc:asdftSin0nrelviNeK");

            int result = FuzzyHashing.Compare(signature, signatureToCompare);

            Console.WriteLine("signature:          " + signature);
            Console.WriteLine("signatureToCompare: " + signatureToCompare);
            Console.WriteLine("Similarity:         " + result);
        }

        /// <summary>
        ///A test for Calculate
        ///</summary>
        [TestMethod()]
        public void CalculateTest()
        {
            Stream stream = null; // TODO: Initialize to an appropriate value
            SpamSumSignature expected = null; // TODO: Initialize to an appropriate value
            SpamSumSignature actual;
            actual = FuzzyHashing.Calculate(stream);
            Assert.AreEqual(expected, actual);
            Assert.Inconclusive("Verify the correctness of this test method.");
        }

        /// <summary>
        ///A test for Calculate
        ///</summary>
        [TestMethod()]
        public void CalculateTest1()
        {
            string filename = string.Empty; // TODO: Initialize to an appropriate value
            SpamSumSignature expected = null; // TODO: Initialize to an appropriate value
            SpamSumSignature actual;
            actual = FuzzyHashing.Calculate(filename);
            Assert.AreEqual(expected, actual);
            Assert.Inconclusive("Verify the correctness of this test method.");
        }

        /// <summary>
        ///A test for Compare
        ///</summary>
        [TestMethod()]
        public void CompareTest()
        {
            SpamSumSignature signature1 = null; // TODO: Initialize to an appropriate value
            SpamSumSignature signature2 = null; // TODO: Initialize to an appropriate value
            int expected = 0; // TODO: Initialize to an appropriate value
            int actual;
            actual = FuzzyHashing.Compare(signature1, signature2);
            Assert.AreEqual(expected, actual);
            Assert.Inconclusive("Verify the correctness of this test method.");
        }
    }
}
