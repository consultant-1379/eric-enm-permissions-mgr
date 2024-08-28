#!python
#cython: language_level=3

# Include the appropriate C header file that defines 'bool'
cdef extern from "stdbool.h":
    ctypedef int bool
    cdef int true "true"
    cdef int false "false"

cdef extern from "permissions_changer.h":

    int set_group_user(
        char* directory,
        int uid_to_set,
        int gid_to_set,
        int set_uid,
        int set_gid,
        int set_sticky_bit,
        char* breakpoints,
        char* exclusion,
        bool root_squash
    )

    int set_permissions(
        char* directory,
        char* dirmode,
        char* filemode,
        char* file_ext_pemissions,
        int uid_to_set,
        int gid_to_set,
        char* breakpoints,
        char* exclusion,
        char* environment_type,
        char* exclude_files
    )

    int run_chown(
        char* directory,
        int uid_to_set,
        int gid_to_set
    )

    int get_directory_counter()
    int get_file_counter()

def directory_counter():
    return get_directory_counter()

def file_counter():
    return directory_counter()

def change_group_permissions(directory, int uid_to_set, int gid_to_set, int set_uid, int set_gid, int set_sticky_bit, breakpoints, exclusion, root_squash):
    set_group_user(
        directory,
        uid_to_set,
        gid_to_set,
        set_uid,
        set_gid,
        set_sticky_bit,
        breakpoints,
        exclusion,
        root_squash
    )

def change_permissions(directory, dirmode, filemode, file_ext_pemissions, int uid_to_set, int gid_to_set, breakpoints, exclusion, char* environment_type, exclude_files):
        set_permissions(
        directory,
        dirmode,
        filemode,
        file_ext_pemissions,
        uid_to_set, gid_to_set,
        breakpoints,
        exclusion,
        environment_type,
        exclude_files
    )

def call_chown(directory, int uid_to_set, int gid_to_set):
    return run_chown(
        directory,
        uid_to_set, 
        gid_to_set
    )

