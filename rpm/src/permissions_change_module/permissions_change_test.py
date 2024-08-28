#!python
#cython: language_level=3
##########################################################################
# COPYRIGHT Ericsson 2023
#
# The copyright to the computer program(s) herein is the property of
# Ericsson Inc. The programs may be used and/or copied only with written
# permission from Ericsson Inc. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
###########################################################################
# This is a test script for the permissions change module
from permissions_change import change_permissions
# from permissions_change import list_exclusions
# from permissions_change import del_exclusions

import array
a=array.array('i', [205,306])


# change_group_permissions(b"foo", a)

# change_group_permissions(b"foo", a, 205, 306, b"foo2")
# change_group_permissions(b"foo", a, 205, 306, b"bar,baz")
# (directory, dirmode, filemode, file_ext_pemissions, int uid_to_set, int gid_to_set, exclusion)
change_permissions(b"foo", b"777", b"000", b"xml,660,sh,770,txt,740", a, 306, b"foo/test.txt,foo.bar,foo.baz")
# add_new_exclusion(b"test1")
# list_exclusions()
# del_exclusions()
# add_new_exclusion(b"test3")
# add_new_exclusion(b"test4")
# list_exclusions()
#change_group_permissions_not_process_owner(b"foo", a, 205, 306)
