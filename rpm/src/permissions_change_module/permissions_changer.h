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
);


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
);

int run_chown(
    char* directory,
    int uid_to_set, 
    int gid_to_set
);

int get_directory_counter();
int get_file_counter();
