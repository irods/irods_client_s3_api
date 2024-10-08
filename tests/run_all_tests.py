import unittest
import getobject_test
import copyobject_test
import deleteobject_test
import getobject_test
import headobject_test
import headbucket_test
import listbuckets_test
import listobject_test
import putobject_test
import abortmultipartupload_test


def run_some_tests():
    # Run only the tests in the specified classes

    test_classes_to_run = [
            copyobject_test.CopyObject_Test,
            deleteobject_test.DeleteObject_Test,
            getobject_test.GetObject_Test,
            headbucket_test.HeadBucket_Test,
            headobject_test.HeadObject_Test,
            listbuckets_test.ListBuckets_Test,
            listobject_test.ListObject_Test,
            putobject_test.PutObject_Test,
            abortmultipartupload_test.AbortMultipartUpload_Test]

    loader = unittest.TestLoader()

    suites_list = []
    for test_class in test_classes_to_run:
        suite = loader.loadTestsFromTestCase(test_class)
        suites_list.append(suite)

    big_suite = unittest.TestSuite(suites_list)

    runner = unittest.TextTestRunner()
    results = runner.run(big_suite)

    # ...

if __name__ == '__main__':
    run_some_tests()
