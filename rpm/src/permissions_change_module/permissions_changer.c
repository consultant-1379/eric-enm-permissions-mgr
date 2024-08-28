#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include "permissions_changer.h"
#include <assert.h>
#include <fcntl.h>

/// For metrics
int file_counter = 0;
int directory_counter = 0;

mode_t permissions_string_to_file_mode(char* filemode){
    mode_t st_mode = S_IRUSR & S_IXUSR;
    printf("testing");
    printf(filemode);
    if (strlen(filemode) > 4){
        //TODO handle permissions strings like -rw-r--r--.
        return st_mode;
    } else if(strlen(filemode) == 4){
        switch(filemode[0]){
            case '0': st_mode = ~(S_ISUID | S_ISGID| S_ISVTX);break;
            case '1': st_mode = ~(S_ISUID | S_ISGID) & S_ISVTX;break;
            case '2': st_mode = ~(S_ISUID | S_ISVTX) & S_ISGID;break;
            case '3': st_mode = ~(S_ISUID) & S_ISGID | S_ISVTX;break;
            case '4': st_mode = ~(S_ISUID | S_ISVTX) & S_ISUID;break;
            case '5': st_mode = ~(S_ISGID) & S_ISUID | S_ISVTX;break;
            case '6': st_mode = ~(S_ISVTX) & S_ISUID | S_ISGID;break;
            case '7': st_mode = S_ISUID | S_ISGID | S_ISVTX;break;
        }
        switch(filemode[1]){
            case '0': break;
            case '1': st_mode = S_IXUSR;break;
            case '2': st_mode = st_mode | S_IWUSR;break;
            case '3': st_mode = st_mode | S_IWUSR | S_IXUSR;break;
            case '4': st_mode = st_mode | S_IRUSR;break;
            case '5': st_mode = st_mode | S_IRUSR | S_IXUSR;break;
            case '6': st_mode = st_mode | S_IRUSR | S_IWUSR;break;
            case '7': st_mode = st_mode | S_IRUSR | S_IWUSR | S_IXUSR;break;
        }
        switch(filemode[2]){
            case '0': break;
            case '1': st_mode = st_mode | S_IXGRP;break;
            case '2': st_mode = st_mode | S_IWGRP;break;
            case '3': st_mode = st_mode | S_IWGRP | S_IXGRP;break;
            case '4': st_mode = st_mode | S_IRGRP;break;
            case '5': st_mode = st_mode | S_IRGRP | S_IXGRP;break;
            case '6': st_mode = st_mode | S_IRGRP | S_IWGRP;break;
            case '7': st_mode = st_mode | S_IRGRP | S_IWGRP | S_IXGRP;break;
        }
        switch(filemode[3]){
            case '0': break;
            case '1': st_mode = st_mode | S_IXOTH;break;
            case '2': st_mode = st_mode | S_IWOTH;break;
            case '3': st_mode = st_mode | S_IWOTH | S_IXOTH;break;
            case '4': st_mode = st_mode | S_IROTH;break;
            case '5': st_mode = st_mode | S_IROTH | S_IXOTH;break;
            case '6': st_mode = st_mode | S_IROTH | S_IWOTH;break;
            case '7': st_mode = st_mode | S_IROTH | S_IWOTH | S_IXOTH;break;
        }
        return st_mode;
    } else {
        switch(filemode[0]){
            case '0': break;
            case '1': st_mode = S_IXUSR;break;
            case '2': st_mode = st_mode | S_IWUSR;break;
            case '3': st_mode = st_mode | S_IWUSR | S_IXUSR;break;
            case '4': st_mode = st_mode | S_IRUSR;break;
            case '5': st_mode = st_mode | S_IRUSR | S_IXUSR;break;
            case '6': st_mode = st_mode | S_IRUSR | S_IWUSR;break;
            case '7': st_mode = st_mode | S_IRUSR | S_IWUSR | S_IXUSR;break;
        }
        switch(filemode[1]){
            case '0': break;
            case '1': st_mode = st_mode | S_IXGRP;break;
            case '2': st_mode = st_mode | S_IWGRP;break;
            case '3': st_mode = st_mode | S_IWGRP | S_IXGRP;break;
            case '4': st_mode = st_mode | S_IRGRP;break;
            case '5': st_mode = st_mode | S_IRGRP | S_IXGRP;break;
            case '6': st_mode = st_mode | S_IRGRP | S_IWGRP;break;
            case '7': st_mode = st_mode | S_IRGRP | S_IWGRP | S_IXGRP;break;
        }
        switch(filemode[2]){
            case '0': break;
            case '1': st_mode = st_mode | S_IXOTH;break;
            case '2': st_mode = st_mode | S_IWOTH;break;
            case '3': st_mode = st_mode | S_IWOTH | S_IXOTH;break;
            case '4': st_mode = st_mode | S_IROTH;break;
            case '5': st_mode = st_mode | S_IROTH | S_IXOTH; break;
            case '6': st_mode = st_mode | S_IROTH | S_IWOTH;break;
            case '7': st_mode = st_mode | S_IROTH | S_IWOTH | S_IXOTH;break;
        }
        st_mode = st_mode & ~(S_ISUID | S_ISGID | S_ISVTX);
    }    
    return st_mode;
    
}

// Define a mapping between a filemode and file extension
typedef struct exclusionKeyPair {
    char* key;
    int exclude;
    struct exclusionKeyPair* next;
} ExclusionKeyPair;

typedef struct exclusionsmap {
    ExclusionKeyPair** list;       // Pair* list
    unsigned int cap;  // capacity, the length of list
    unsigned int len;  // length, the number of pairs
} ExclusionsMap;

unsigned exclusionsMapHashCode(ExclusionsMap* this, char* key) {
    unsigned code;
    for (code = 0; *key != '\0'; key++) {
        code = *key + 31 * code;
    }
    return code % (this->cap);
}

ExclusionsMap* newExclusionsMap() {
    ExclusionsMap* this = malloc(sizeof(this));
    this->cap = 8;  // set default capacity
    this->len = 0;  // no pair in map
    // set all pointer to null in this->list
    this->list = calloc((this->cap), sizeof(ExclusionKeyPair*));
    return this;
}

typedef struct {
    char path[PATH_MAX];
} PathStackItem;

void push(PathStackItem** stack, int* size, int* capacity, PathStackItem item) {
    if (*size >= *capacity) {
        *capacity *= 2;
        *stack = realloc(*stack, sizeof(PathStackItem) * (*capacity));
        if (!*stack) {
            perror("Failed to reallocate stack memory");
            exit(EXIT_FAILURE);
        }
    }
    (*stack)[(*size)++] = item;
}

PathStackItem pop(PathStackItem** stack, int* size) {
    return (*stack)[--(*size)];
}

int getExclusionsKeyPair(ExclusionsMap* this, char* key) {
    ExclusionKeyPair* current;
    for (current = this->list[exclusionsMapHashCode(this, key)]; current;
         current = current->next) {
        if (!strcmp(current->key, key)) {
            return current->exclude;
        }
    }
    return -1;
}

// If key is not in hashmap, put into map. Otherwise, replace it.
void setExclusionKeyPair(ExclusionsMap* this, char* key, bool exclude) {
    unsigned index = exclusionsMapHashCode(this, key);
    ExclusionKeyPair* current;
    for (current = this->list[index]; current; current = current->next) {
        // if key has been already in hashmap
        if (!strcmp(current->key, key)) {
            current->exclude = 1;
            return;
        }
    }

    // key is not in mimemap
    ExclusionKeyPair* p = malloc(sizeof(*p));
    p->key = key;
    p->exclude = true;
    p->next = this->list[index];
    this->list[index] = p;
    this->len++;
}


ExclusionsMap* exclusionsSplit(char a_str[], char delim) {
    ExclusionsMap* exclusionsmap = newExclusionsMap();
    if(a_str[0] == '\0'){return exclusionsmap;}
    char *filepath =  strtok(a_str, &delim);
    setExclusionKeyPair(exclusionsmap, filepath, true);
    while(filepath != NULL){
        filepath = strtok(NULL, &delim);
        if(filepath != '\0'){
            // printf("%s\n",filepath);
            setExclusionKeyPair(exclusionsmap, filepath, true);
        }
    }
    return exclusionsmap;
}


typedef struct filemodeResult {
    mode_t filemode;
    int result;
} FilemodeResult;

// Define a mapping between a filemode and file extension
typedef struct filemodeKeyPair {
    char* key;
    FilemodeResult res;
    struct filemodeKeyPair* next;
} FilemodeKeyPair;

typedef struct mimemap {
    FilemodeKeyPair** list;       // Pair* list
    unsigned int cap;  // capacity, the length of list
    unsigned int len;  // length, the number of pairs
} MimeMap;

unsigned hashcode(MimeMap* this, char* key) {
    unsigned code;
    for (code = 0; *key != '\0'; key++) {
        code = *key + 31 * code;
    }
    return code % (this->cap);
}

MimeMap* newMimeMap() {
    MimeMap* this = malloc(sizeof(this));
    this->cap = 8;  // set default capacity
    this->len = 0;  // no pair in map
    // set all pointer to null in this->list
    this->list = calloc((this->cap), sizeof(FilemodeKeyPair*));
    return this;
}

FilemodeResult defaultres ={S_IWUSR,-1};
FilemodeResult getMimeMap(MimeMap* this, char* key) {
    FilemodeKeyPair* current;
    for (current = this->list[hashcode(this, key)]; current;
         current = current->next) {
        if (!strcmp(current->key, key)) {
            return current->res;
        }
    }
    return defaultres;
}

// If key is not in hashmap, put into map. Otherwise, replace it.
void setFilemodeKeyPair(MimeMap* this, char* key, mode_t filemode) {
    unsigned index = hashcode(this, key);
    FilemodeKeyPair* current;
    for (current = this->list[index]; current; current = current->next) {
        // if key has been already in hashmap
        if (!strcmp(current->key, key)) {
            current->res.filemode = filemode;
            return;
        }
    }

    // key is not in mimemap
    FilemodeKeyPair* p = malloc(sizeof(*p));
    p->key = key;
    p->res.filemode = filemode;
    p->next = this->list[index];
    this->list[index] = p;
    this->len++;
}


MimeMap* mimeSplit(char a_str[], char delim) {
    size_t count     = 0;
    char* tmp        = a_str;
    MimeMap* m = newMimeMap();

    while (*tmp) {
        if (delim == (char) *tmp) {
            count++;
        } 
        tmp++;
    }
    char *p =  strtok(a_str, &delim);
    tmp = p;
    int idx = 1;
    while(p != NULL){
        if(idx % 2 != 0){
            p = strtok(NULL, &delim);
            setFilemodeKeyPair(m, tmp, permissions_string_to_file_mode(p));
        } else {
            p = strtok(NULL, &delim);
            tmp = p;
        }
        idx = idx + 1;
    }
    return m;
}



char* get_filename_ext(char *filename) {
    char* dot = strrchr(filename, '.');
    if(!dot || dot == filename) return "";
    return dot + 1;
}

struct splitString {
  int length;
  char **array;
};

struct splitString split(char a_str[], char delim) {
    size_t count     = 0;
    char* tmp        = a_str;

    while (*tmp) {
        if (delim == (char) *tmp) {
            count++;
        } 
        tmp++;
    }

    struct splitString result;
    result.array = malloc(sizeof(char*) * count);

    
    result.length = 0;
    char *p =  strtok(a_str, &delim);
    while(p != NULL){
        result.array[result.length++] = p;
        p = strtok(NULL, &delim);
    }
    return result;
}

void print_mode_permissions(mode_t stmode){
    printf( (S_ISDIR(stmode)) ? "d" : "-");
    printf( (stmode & S_ISUID) ? "s" : "-");
    printf( (stmode & S_ISGID) ? "S" : "-");
    printf( (stmode & S_ISVTX) ? "T" : "-");
    printf( (stmode & S_IRUSR) ? "r" : "-");
    printf( (stmode & S_IWUSR) ? "w" : "-");
    printf( (stmode & S_IXUSR) ? "x" : "-");
    printf( (stmode & S_IRGRP) ? "r" : "-");
    printf( (stmode & S_IWGRP) ? "w" : "-");
    printf( (stmode & S_IXGRP) ? "x" : "-");
    printf( (stmode & S_IROTH) ? "r" : "-");
    printf( (stmode & S_IWOTH) ? "w" : "-");
    printf( (stmode & S_IXOTH) ? "x" : "-");
    printf("\n\n");
}

int file_in_exclusions(char * directory, struct splitString exclusions){
    if (exclusions.array) {
        int i;
        for (i = 0; i < exclusions.length; i++) {
            printf("%s:%s\n", exclusions.array[i], directory);
            if(strcmp(exclusions.array[i], directory) == 0) {
                printf("match \n");
                return 1;
            }
        }
    } return 0;
}

int set_group_equal_user_root(char* directory, int uid, int gid, int auid, int agid, mode_t directory_mode_set, ExclusionsMap* exclusions){
    if(getExclusionsKeyPair(exclusions, directory) != -1){return 0;}
    // Sets the group equal to the user when not the process owner or root
    struct stat fileStat;
    int result;
    if(stat(directory, &fileStat) < 0)
        return 1;

    gid_t egid = gid;
    gid_t aegid = agid;

    // Run g=u
    if ((fileStat.st_mode & S_IRUSR) && !(fileStat.st_mode & S_IRGRP)) {
        fileStat.st_mode = fileStat.st_mode | S_IRGRP; // add permission to group if the user has it
    } else if (!(fileStat.st_mode & S_IRUSR) && (fileStat.st_mode & S_IRGRP)) {
        fileStat.st_mode &= ~(S_IRGRP); // remove permission from group if the user doesn't have it
    }
    if ((fileStat.st_mode & S_IWUSR) && !(fileStat.st_mode & S_IWGRP)) {
        fileStat.st_mode = fileStat.st_mode | S_IWGRP;
    }else if (!(fileStat.st_mode & S_IWUSR) && (fileStat.st_mode & S_IWGRP)) {
        fileStat.st_mode &= ~(S_IWGRP);
    }

    if(S_ISDIR(fileStat.st_mode)){
        // Ensures that directories can always be listed by the group using ls command.
        fileStat.st_mode = fileStat.st_mode | directory_mode_set;
        printf("Directory %s updated to", directory);
        result = chown(directory, auid, egid);
        result = chmod(directory, fileStat.st_mode);
        directory_counter = directory_counter + 1;
        if(stat(directory, &fileStat) < 0)    
            return 1;

        print_mode_permissions(fileStat.st_mode);
        
        DIR *newdirectory;
        struct dirent *file;
        newdirectory = opendir(directory);
        while((file = readdir(newdirectory)))
        {
            if( file->d_name[0] != '.' )
            {
                char buffer[4095];
                sprintf(buffer, "%s/%s", directory, file->d_name);
                set_group_equal_user_root(buffer, uid, gid, auid, agid, directory_mode_set, exclusions);
            }
        }
    }
    else if(S_ISREG(fileStat.st_mode)){
        if ((fileStat.st_mode & S_IXUSR) && !(fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode = fileStat.st_mode | S_IXGRP;
        } else if (!(fileStat.st_mode & S_IXUSR) && (fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode &= ~(S_IXGRP);
        }
        
        result = chown(directory, auid, aegid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, fileStat.st_mode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        file_counter = file_counter + 1;

        print_mode_permissions(fileStat.st_mode);
    }
    return 0;
}


int gu_breakpoint_chmod_user_root(char* directory, int uid, int gid, int auid, int agid, mode_t directory_mode_set, ExclusionsMap* exclusions){
    if(getExclusionsKeyPair(exclusions, directory) != -1){return 0;}
    // Sets the group equal to the user when not the process owner or root
    struct stat fileStat;
    int result;
    if(stat(directory, &fileStat) < 0)    
        return 1;

    gid_t egid = gid;
    gid_t aegid = agid;

    // Run g=u
    if ((fileStat.st_mode & S_IRUSR) && !(fileStat.st_mode & S_IRGRP)) {
        fileStat.st_mode = fileStat.st_mode | S_IRGRP; // add permission to group if the user has it
    } else if (!(fileStat.st_mode & S_IRUSR) && (fileStat.st_mode & S_IRGRP)) {
        fileStat.st_mode &= ~(S_IRGRP); // remove permission from group if the user doesn't have it
    }
    if ((fileStat.st_mode & S_IWUSR) && !(fileStat.st_mode & S_IWGRP)) {
        fileStat.st_mode = fileStat.st_mode | S_IWGRP;
    }else if (!(fileStat.st_mode & S_IWUSR) && (fileStat.st_mode & S_IWGRP)) {
        fileStat.st_mode &= ~(S_IWGRP);
    }

    if(S_ISDIR(fileStat.st_mode)){
        // Ensures that directories can always be listed by the group using ls command.
        fileStat.st_mode = fileStat.st_mode | directory_mode_set;
        printf("Directory %s updated to", directory);
        result = chown(directory, auid, egid);
        result = chmod(directory, fileStat.st_mode);
        directory_counter = directory_counter + 1;
        if(stat(directory, &fileStat) < 0)    
            return 1;

        print_mode_permissions(fileStat.st_mode);
    }
    else if(S_ISREG(fileStat.st_mode)){
        if ((fileStat.st_mode & S_IXUSR) && !(fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode = fileStat.st_mode | S_IXGRP;
        } else if (!(fileStat.st_mode & S_IXUSR) && (fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode &= ~(S_IXGRP);
        }
        
        result = chown(directory, auid, aegid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, fileStat.st_mode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        file_counter = file_counter + 1;

        print_mode_permissions(fileStat.st_mode);
    }
    return 0;
}


int set_group_equal_user_root_breakpoint(char* directory, int uid, int gid, int auid, int agid, mode_t directory_mode_set, ExclusionsMap* exclusions){
    
    // Sets the group equal to the user when not the process owner or root
    struct stat fileStat;
    int result;
    if(stat(directory, &fileStat) < 0)    
        return 1;

    gid_t egid = gid;
    gid_t aegid = agid;

    // Run g=u
    if ((fileStat.st_mode & S_IRUSR) && !(fileStat.st_mode & S_IRGRP)) {
        fileStat.st_mode = fileStat.st_mode | S_IRGRP; // add permission to group if the user has it
    } else if (!(fileStat.st_mode & S_IRUSR) && (fileStat.st_mode & S_IRGRP)) {
        fileStat.st_mode &= ~(S_IRGRP); // remove permission from group if the user doesn't have it
    }
    if ((fileStat.st_mode & S_IWUSR) && !(fileStat.st_mode & S_IWGRP)) {
        fileStat.st_mode = fileStat.st_mode | S_IWGRP;
    }else if (!(fileStat.st_mode & S_IWUSR) && (fileStat.st_mode & S_IWGRP)) {
        fileStat.st_mode &= ~(S_IWGRP);
    }

    if(S_ISDIR(fileStat.st_mode)){
        // Ensures that directories can always be listed by the group using ls command.
        fileStat.st_mode = fileStat.st_mode | directory_mode_set;
        printf("Directory %s updated to", directory);
        result = chown(directory, auid, egid);
        result = chmod(directory, fileStat.st_mode);
        directory_counter = directory_counter + 1;
        if(stat(directory, &fileStat) < 0)    
            return 1;

        print_mode_permissions(fileStat.st_mode);
        
        DIR *newdirectory;
        struct dirent *file;
        newdirectory = opendir(directory);
        while((file = readdir(newdirectory)))
        {
            if( file->d_name[0] != '.' )
            {
                char buffer[4095];
                sprintf(buffer, "%s/%s", directory, file->d_name);
                set_group_equal_user_root(buffer, uid, gid, auid, agid, directory_mode_set, exclusions);
            }
        }
    }
    else if(S_ISREG(fileStat.st_mode)){
        if ((fileStat.st_mode & S_IXUSR) && !(fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode = fileStat.st_mode | S_IXGRP;
        } else if (!(fileStat.st_mode & S_IXUSR) && (fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode &= ~(S_IXGRP);
        }
        
        result = chown(directory, auid, aegid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, fileStat.st_mode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        file_counter = file_counter + 1;

        print_mode_permissions(fileStat.st_mode);
    }
    return 0;
}


int get_directory_counter(){
    return directory_counter;
}

int get_file_counter(){
    return file_counter;
}

int set_group_equal_user_not_process_owner(char* directory, int uid, int gid,  int auid, int agid, mode_t directory_mode_set, ExclusionsMap* exclusions){
    if(getExclusionsKeyPair(exclusions, directory) != -1){return 0;}
    // Sets the group equal to the user when not the process owner or root
    struct stat fileStat;

    int result;
    if(stat(directory, &fileStat) < 0)
        return 1;

    // There is a bug for directory permissions where the stat command returns nonsense e.g d------------ with 0 permissions causing the command to fail
    // As a result we must never trust stat results on directories.
    print_mode_permissions(fileStat.st_mode);

    gid_t egid = gid;
    gid_t aegid = agid;

    if(S_ISDIR(fileStat.st_mode)){
        int dirfd = open(directory, O_RDONLY);
        struct stat st;
        int r = fstatat(dirfd, directory , &fileStat, 0);
        printf("testdirectory");
        print_mode_permissions(fileStat.st_mode);

        // Ensures that directories can always be listed by the group using ls command.
        fileStat.st_mode = fileStat.st_mode | directory_mode_set;
        result = chown(directory, uid, egid);
        result = chmod(directory, fileStat.st_mode);
        directory_counter = directory_counter + 1;
        if(stat(directory, &fileStat) < 0)
            return 1;

        printf("directory");
        print_mode_permissions(fileStat.st_mode);

        DIR *newdirectory;
        struct dirent *file;
        newdirectory = opendir(directory);
        while((file = readdir(newdirectory)))
        {
            if( file->d_name[0] != '.' )
            {
                char buffer[4095];
                sprintf(buffer, "%s/%s", directory, file->d_name);
                set_group_equal_user_not_process_owner(buffer, uid, gid, auid, agid, directory_mode_set, exclusions);
            }
        }

        printf("auid %d", auid);
        result = chown(directory, auid, aegid);
    }
    else if(S_ISREG(fileStat.st_mode)){

        // Run g=u
        if ((fileStat.st_mode & S_IRUSR) && !(fileStat.st_mode & S_IRGRP)) {
            fileStat.st_mode = fileStat.st_mode | S_IRGRP; // add permission to group if the user has it
        } else if (!(fileStat.st_mode & S_IRUSR) && (fileStat.st_mode & S_IRGRP)) {
            fileStat.st_mode &= ~(S_IRGRP); // remove permission from group if the user doesn't have it
        }
        if ((fileStat.st_mode & S_IWUSR) && !(fileStat.st_mode & S_IWGRP)) {
            fileStat.st_mode = fileStat.st_mode | S_IWGRP;
        }else if (!(fileStat.st_mode & S_IWUSR) && (fileStat.st_mode & S_IWGRP)) {
            fileStat.st_mode &= ~(S_IWGRP);
        }


        if ((fileStat.st_mode & S_IXUSR) && !(fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode = fileStat.st_mode | S_IXGRP;
        } else if (!(fileStat.st_mode & S_IXUSR) && (fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode &= ~(S_IXGRP);
        }

        result = chown(directory, uid, egid);
        printf("file %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, fileStat.st_mode);
        printf("Result of chmod command %d\n", result);
        printf("auid: %d", auid);
        result = chown(directory, auid, aegid);
        printf("Result of chown command %d\n", result);
        if(stat(directory, &fileStat) < 0)
            return 1;
        file_counter = file_counter + 1;
        print_mode_permissions(fileStat.st_mode);
    }
    return 0;
}

int set_group_equal_user_not_process_owner_root_squash(char* directory, int uid, int gid,  int auid, int agid, mode_t directory_mode_set, ExclusionsMap* exclusions){
    if(getExclusionsKeyPair(exclusions, directory) != -1){return 0;}
    // Sets the group equal to the user when not the process owner or root
    struct stat fileStat;

    int result;
    if(stat(directory, &fileStat) < 0)
        return 1;

    // There is a bug for directory permissions where the stat command returns nonsense e.g d------------ with 0 permissions causing the command to fail
    // As a result we must never trust stat results on directories.
    print_mode_permissions(fileStat.st_mode);

    gid_t egid = gid;
    gid_t aegid = agid;

    if(S_ISDIR(fileStat.st_mode)){
        int dirfd = open(directory, O_RDONLY);
        struct stat st;
        int r = fstatat(dirfd, directory, &fileStat, 0);
        printf("testdirectory");
        print_mode_permissions(fileStat.st_mode);

        // Ensures that directories can always be listed by the group using ls command.
        fileStat.st_mode = fileStat.st_mode | directory_mode_set;
        result = chmod(directory, fileStat.st_mode);
        directory_counter = directory_counter + 1;
        if(stat(directory, &fileStat) < 0)
            return 1;

        printf("directory");
        print_mode_permissions(fileStat.st_mode);

        DIR *newdirectory;
        struct dirent *file;
        newdirectory = opendir(directory);
        while((file = readdir(newdirectory)))
        {
            if( file->d_name[0] != '.' )
            {
                char buffer[4095];
                sprintf(buffer, "%s/%s", directory, file->d_name);
                set_group_equal_user_not_process_owner_root_squash(buffer, uid, gid, auid, agid, directory_mode_set, exclusions);
            }
        }
    }
    else if(S_ISREG(fileStat.st_mode)){

        // Run g=u
        if ((fileStat.st_mode & S_IRUSR) && !(fileStat.st_mode & S_IRGRP)) {
            fileStat.st_mode = fileStat.st_mode | S_IRGRP; // add permission to group if the user has it
        } else if (!(fileStat.st_mode & S_IRUSR) && (fileStat.st_mode & S_IRGRP)) {
            fileStat.st_mode &= ~(S_IRGRP); // remove permission from group if the user doesn't have it
        }
        if ((fileStat.st_mode & S_IWUSR) && !(fileStat.st_mode & S_IWGRP)) {
            fileStat.st_mode = fileStat.st_mode | S_IWGRP;
        }else if (!(fileStat.st_mode & S_IWUSR) && (fileStat.st_mode & S_IWGRP)) {
            fileStat.st_mode &= ~(S_IWGRP);
        }

        if ((fileStat.st_mode & S_IXUSR) && !(fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode = fileStat.st_mode | S_IXGRP;
        } else if (!(fileStat.st_mode & S_IXUSR) && (fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode &= ~(S_IXGRP);
        }

        result = chmod(directory, fileStat.st_mode);
        printf("Result of chmod command %d\n", result);
        printf("auid: %d", auid);
        if(stat(directory, &fileStat) < 0)
            return 1;
        file_counter = file_counter + 1;
        print_mode_permissions(fileStat.st_mode);
    }
    return 0;
}

int gu_breakpoint_chmod_user_not_process_owner(char* directory,  int uid, int gid,  int auid, int agid, mode_t directory_mode_set, ExclusionsMap* exclusions){
    if(getExclusionsKeyPair(exclusions, directory) != -1){return 0;}
    // Sets the group equal to the user when not the process owner or root
    struct stat fileStat;

    int result;
    if(stat(directory, &fileStat) < 0)    
        return 1;
    
    gid_t egid = gid;
    gid_t aegid = agid;
    
    // Run g=u
    if ((fileStat.st_mode & S_IRUSR) && !(fileStat.st_mode & S_IRGRP)) {
        fileStat.st_mode = fileStat.st_mode | S_IRGRP; // add permission to group if the user has it
    } else if (!(fileStat.st_mode & S_IRUSR) && (fileStat.st_mode & S_IRGRP)) {
        fileStat.st_mode &= ~(S_IRGRP); // remove permission from group if the user doesn't have it
    }
    if ((fileStat.st_mode & S_IWUSR) && !(fileStat.st_mode & S_IWGRP)) {
        fileStat.st_mode = fileStat.st_mode | S_IWGRP;
    }else if (!(fileStat.st_mode & S_IWUSR) && (fileStat.st_mode & S_IWGRP)) {
        fileStat.st_mode &= ~(S_IWGRP);
    }

    if(S_ISDIR(fileStat.st_mode)){
        // Ensures that directories can always be listed by the group using ls command.
        fileStat.st_mode = fileStat.st_mode | directory_mode_set;
        result = chown(directory, uid, egid);
        result = chmod(directory, fileStat.st_mode);
        directory_counter = directory_counter + 1;
        if(stat(directory, &fileStat) < 0)    
            return 1;

        print_mode_permissions(fileStat.st_mode);
        printf("auid %d", auid);
        result = chown(directory, auid, aegid);
    }
    else if(S_ISREG(fileStat.st_mode)){
        if ((fileStat.st_mode & S_IXUSR) && !(fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode = fileStat.st_mode | S_IXGRP;
        } else if (!(fileStat.st_mode & S_IXUSR) && (fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode &= ~(S_IXGRP);
        }
        
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, fileStat.st_mode);
        printf("Result of chmod command %d\n", result);
        printf("auid: %d", auid);
        result = chown(directory, auid, aegid);
        printf("Result of chown command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        file_counter = file_counter + 1;
        print_mode_permissions(fileStat.st_mode);
    }
    return 0;
}

int set_group_equal_user_not_process_owner_breakpoint(char* directory,  int uid, int gid,  int auid, int agid, mode_t directory_mode_set, ExclusionsMap* exclusions){

    // Sets the group equal to the user when not the process owner or root
    struct stat fileStat;

    int result;
    if(stat(directory, &fileStat) < 0)    
        return 1;
    
    gid_t egid = gid;
    gid_t aegid = agid;
    
    // Run g=u
    if ((fileStat.st_mode & S_IRUSR) && !(fileStat.st_mode & S_IRGRP)) {
        fileStat.st_mode = fileStat.st_mode | S_IRGRP; // add permission to group if the user has it
    } else if (!(fileStat.st_mode & S_IRUSR) && (fileStat.st_mode & S_IRGRP)) {
        fileStat.st_mode &= ~(S_IRGRP); // remove permission from group if the user doesn't have it
    }
    if ((fileStat.st_mode & S_IWUSR) && !(fileStat.st_mode & S_IWGRP)) {
        fileStat.st_mode = fileStat.st_mode | S_IWGRP;
    }else if (!(fileStat.st_mode & S_IWUSR) && (fileStat.st_mode & S_IWGRP)) {
        fileStat.st_mode &= ~(S_IWGRP);
    }

    if(S_ISDIR(fileStat.st_mode)){
        // Ensures that directories can always be listed by the group using ls command.
        fileStat.st_mode = fileStat.st_mode | directory_mode_set;
        result = chown(directory, uid, egid);
        result = chmod(directory, fileStat.st_mode);
        directory_counter = directory_counter + 1;
        if(stat(directory, &fileStat) < 0)    
            return 1;

        print_mode_permissions(fileStat.st_mode);
        
        DIR *newdirectory;
        struct dirent *file;
        newdirectory = opendir(directory);
        while((file = readdir(newdirectory)))
        {
            if( file->d_name[0] != '.' )
            {
                char buffer[4095];
                sprintf(buffer, "%s/%s", directory, file->d_name);
                gu_breakpoint_chmod_user_not_process_owner(buffer, uid, gid, auid, agid, directory_mode_set, exclusions);
            }
        }

        printf("auid %d", auid);
        result = chown(directory, auid, aegid);
    }
    else if(S_ISREG(fileStat.st_mode)){
        if ((fileStat.st_mode & S_IXUSR) && !(fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode = fileStat.st_mode | S_IXGRP;
        } else if (!(fileStat.st_mode & S_IXUSR) && (fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode &= ~(S_IXGRP);
        }
        
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, fileStat.st_mode);
        printf("Result of chmod command %d\n", result);
        printf("auid: %d", auid);
        result = chown(directory, auid, aegid);
        printf("Result of chown command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        file_counter = file_counter + 1;
        print_mode_permissions(fileStat.st_mode);
    }
    return 0;
}

int gu_breakpoint_chmod_user(char* directory, int uid, int gid, mode_t directory_mode_set, ExclusionsMap* exclusions){
    if(getExclusionsKeyPair(exclusions, directory) != -1){return 0;}
    struct stat fileStat;
    gid_t egid = gid;
    int result;
    if(stat(directory, &fileStat) < 0)    
        return 1;
    
    // Run g=u
    if ((fileStat.st_mode & S_IRUSR) && !(fileStat.st_mode & S_IRGRP)) {
        fileStat.st_mode = fileStat.st_mode | S_IRGRP; // add permission to group if the user has it
    } else if (!(fileStat.st_mode & S_IRUSR) && (fileStat.st_mode & S_IRGRP)) {
        fileStat.st_mode &= ~(S_IRGRP); // remove permission from group if the user doesn't have it
    }
    if ((fileStat.st_mode & S_IWUSR) && !(fileStat.st_mode & S_IWGRP)) {
        fileStat.st_mode = fileStat.st_mode | S_IWGRP;
    }else if (!(fileStat.st_mode & S_IWUSR) && (fileStat.st_mode & S_IWGRP)) {
        fileStat.st_mode &= ~(S_IWGRP);
    }

    if(S_ISDIR(fileStat.st_mode)){
        // Ensures that directories can always be listed by the group using ls command.
        fileStat.st_mode = fileStat.st_mode | directory_mode_set;
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, fileStat.st_mode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        directory_counter = directory_counter + 1;
        printf("Directory %s updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
    }
    else if(S_ISREG(fileStat.st_mode)){
        if ((fileStat.st_mode & S_IXUSR) && !(fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode = fileStat.st_mode | S_IXGRP;
        } else if (!(fileStat.st_mode & S_IXUSR) && (fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode &= ~(S_IXGRP);
        }
        
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, fileStat.st_mode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;

        printf("File %s permissions updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
        file_counter = file_counter + 1;
    }
    return 0;
}

int set_group_equal_user_breakpoint(char* directory, int uid, int gid, mode_t directory_mode_set, ExclusionsMap* exclusions){

    struct stat fileStat;
    gid_t egid = gid;
    int result;
    if(stat(directory, &fileStat) < 0)    
        return 1;

    
    // Run g=u
    if ((fileStat.st_mode & S_IRUSR) && !(fileStat.st_mode & S_IRGRP)) {
        fileStat.st_mode = fileStat.st_mode | S_IRGRP; // add permission to group if the user has it
    } else if (!(fileStat.st_mode & S_IRUSR) && (fileStat.st_mode & S_IRGRP)) {
        fileStat.st_mode &= ~(S_IRGRP); // remove permission from group if the user doesn't have it
    }
    if ((fileStat.st_mode & S_IWUSR) && !(fileStat.st_mode & S_IWGRP)) {
        fileStat.st_mode = fileStat.st_mode | S_IWGRP;
    }else if (!(fileStat.st_mode & S_IWUSR) && (fileStat.st_mode & S_IWGRP)) {
        fileStat.st_mode &= ~(S_IWGRP);
    }

    if(S_ISDIR(fileStat.st_mode)){
        // Ensures that directories can always be listed by the group using ls command.
        fileStat.st_mode = fileStat.st_mode | directory_mode_set;
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, fileStat.st_mode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        directory_counter = directory_counter + 1;
        printf("Directory %s updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
        
        DIR *newdirectory;
        struct dirent *file;
        newdirectory = opendir(directory);
        while((file = readdir(newdirectory)))
        {
            if( file->d_name[0] != '.' )
            {
                char buffer[4095];
                sprintf(buffer, "%s/%s", directory, file->d_name);
                gu_breakpoint_chmod_user(buffer, uid, gid, directory_mode_set, exclusions);
            }
        }
    }
    else if(S_ISREG(fileStat.st_mode)){
        if ((fileStat.st_mode & S_IXUSR) && !(fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode = fileStat.st_mode | S_IXGRP;
        } else if (!(fileStat.st_mode & S_IXUSR) && (fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode &= ~(S_IXGRP);
        }
        
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, fileStat.st_mode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;

        printf("File %s permissions updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
        file_counter = file_counter + 1;
    }
    return 0;
}

int set_group_equal_user(char* directory, int uid, int gid, mode_t directory_mode_set, ExclusionsMap* exclusions){
    if(getExclusionsKeyPair(exclusions, directory) != -1){return 0;}
    struct stat fileStat;
    gid_t egid = gid;
    int result;
    if(stat(directory, &fileStat) < 0)    
        return 1;
    
    // Run g=u
    if ((fileStat.st_mode & S_IRUSR) && !(fileStat.st_mode & S_IRGRP)) {
        fileStat.st_mode = fileStat.st_mode | S_IRGRP; // add permission to group if the user has it
    } else if (!(fileStat.st_mode & S_IRUSR) && (fileStat.st_mode & S_IRGRP)) {
        fileStat.st_mode &= ~(S_IRGRP); // remove permission from group if the user doesn't have it
    }
    if ((fileStat.st_mode & S_IWUSR) && !(fileStat.st_mode & S_IWGRP)) {
        fileStat.st_mode = fileStat.st_mode | S_IWGRP;
    }else if (!(fileStat.st_mode & S_IWUSR) && (fileStat.st_mode & S_IWGRP)) {
        fileStat.st_mode &= ~(S_IWGRP);
    }

    if(S_ISDIR(fileStat.st_mode)){
        // Ensures that directories can always be listed by the group using ls command.
        fileStat.st_mode = fileStat.st_mode | directory_mode_set;
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, fileStat.st_mode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        directory_counter = directory_counter + 1;
        printf("Directory %s updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
        
        DIR *newdirectory;
        struct dirent *file;
        newdirectory = opendir(directory);
        while((file = readdir(newdirectory)))
        {
            if( file->d_name[0] != '.' )
            {
                char buffer[4095];
                sprintf(buffer, "%s/%s", directory, file->d_name);
                set_group_equal_user(buffer, uid, gid, directory_mode_set, exclusions);
            }
        }
    }
    else if(S_ISREG(fileStat.st_mode)){
        if ((fileStat.st_mode & S_IXUSR) && !(fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode = fileStat.st_mode | S_IXGRP;
        } else if (!(fileStat.st_mode & S_IXUSR) && (fileStat.st_mode & S_IXGRP)) {
            fileStat.st_mode &= ~(S_IXGRP);
        }
        
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, fileStat.st_mode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;

        printf("File %s permissions updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
        file_counter = file_counter + 1;
    }
    return 0;
}




int set_group_user(char* directory, int uid_to_set, int gid_to_set, int set_uid, int set_gid, int set_sticky_bit, char* breakpoints, char* exclusion, bool root_squash ){

    /**
     * @param directory The directory to change the permissions of.
     * @param uid_to_set The UID specified in mapping xml/yaml to update the file to.
     * @param git_to_set The GID specified in mapping xml/yaml to update the file to.
     */

    uid_t uid = getuid(); // Gets the uid of the user running the process
    gid_t gid = getgid(); // Gets the gid of the user running the process
    uid_t auid = uid_to_set; //convert to ints to uid_t struct
    gid_t agid = gid_to_set;
    
    printf("Exclusion \n");
    printf("%s\n", directory);
    printf("%s\n", exclusion);
    ExclusionsMap* exclusions = exclusionsSplit(exclusion, ',');
    struct splitString splitBreakpoints = split(breakpoints, ',');
    int breakpointCounter = 0;
    while (breakpointCounter < splitBreakpoints.length){
        printf("%s ", splitBreakpoints.array[breakpointCounter]);
        setExclusionKeyPair(exclusions, splitBreakpoints.array[breakpointCounter], true);
        breakpointCounter = breakpointCounter + 1;
    }

    // printf("running as uid %d and gid %d \n", uid, gid);
    mode_t directory_mode_set = S_IXGRP | S_IXUSR | S_IXOTH | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR| S_IWGRP | S_IWOTH;
    if(set_gid == 1){ directory_mode_set = directory_mode_set | S_ISGID; }
    if(set_uid == 1){ directory_mode_set = directory_mode_set | S_ISUID; }
    if(set_sticky_bit == 1){ directory_mode_set = directory_mode_set | S_ISVTX; }
    int res = 0;
    breakpointCounter = 0;
    if (root_squash){
        res = set_group_equal_user_not_process_owner_root_squash(directory, uid, gid, auid, agid, directory_mode_set, exclusions);
        }
    else {
        res = set_group_equal_user_not_process_owner(directory, uid, gid, auid, agid, directory_mode_set, exclusions);
    }
    while (breakpointCounter < splitBreakpoints.length) {
        res = res + set_group_equal_user_not_process_owner_breakpoint(
                splitBreakpoints.array[breakpointCounter], 
                uid, gid, auid, agid, directory_mode_set, exclusions
            );
        breakpointCounter = breakpointCounter + 1;
    } return res;
    printf("Number of directory permissions updated %d \n", directory_counter);
    printf("Number of file permissions updated %d \n", file_counter);
    return res;
}


int breakpoint_chmod_user(char* directory, int uid, int gid, ExclusionsMap* exclusions, mode_t dirmode, mode_t filemode, MimeMap* filemodes){
    if(getExclusionsKeyPair(exclusions, directory) != -1){return 0;}
    struct stat fileStat;
    if(stat(directory, &fileStat) < 0){return 1;}
    gid_t egid = gid;

    int result;
    if(S_ISDIR(fileStat.st_mode)){
        // Ensures that directories can always be listed by the group using ls command.
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, dirmode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        directory_counter = directory_counter + 1;
        printf("Directory %s updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
        
    } else if(S_ISREG(fileStat.st_mode)){
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        FilemodeResult rFilemode = getMimeMap(filemodes, get_filename_ext(directory));
        if(rFilemode.result != -1){
            result = chmod(directory, rFilemode.filemode);
        } else {
            result = chmod(directory, filemode);
        }       
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        file_counter = file_counter + 1;
        printf("File %s permissions updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
    }
    return 0;
}

int set_permissions_user_breakpoint(char* directory, int uid, int gid, ExclusionsMap* exclusions, mode_t dirmode, mode_t filemode, MimeMap* filemodes){
    struct stat fileStat;
    if(stat(directory, &fileStat) < 0){return 1;}
    gid_t egid = gid;

    int result;
    if(S_ISDIR(fileStat.st_mode)){
        // Ensures that directories can always be listed by the group using ls command.
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, dirmode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        directory_counter = directory_counter + 1;
        printf("Directory %s updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
        DIR *newdirectory;
        struct dirent *file;
        newdirectory = opendir(directory);
        file = readdir(newdirectory);
        file = readdir(newdirectory);
        while((file = readdir(newdirectory)))
        {
            char buffer[4095];
            sprintf(buffer, "%s/%s", directory, file->d_name);
            breakpoint_chmod_user(buffer, uid, gid, exclusions, dirmode, filemode, filemodes);
        }
    } else {
        return 1;
    }
    return 0;
}

int set_permissions_user(char* directory, int uid, int gid, ExclusionsMap* exclusions, mode_t dirmode, mode_t filemode, MimeMap* filemodes){
    if(getExclusionsKeyPair(exclusions, directory) != -1){return 0;}
    struct stat fileStat;
    if(stat(directory, &fileStat) < 0){return 1;}
    gid_t egid = gid;

    int result;
    if(S_ISDIR(fileStat.st_mode)){
        // Ensures that directories can always be listed by the group using ls command.
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, dirmode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        directory_counter = directory_counter + 1;
        printf("Directory %s updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
        
        DIR *newdirectory;
        struct dirent *file;
        newdirectory = opendir(directory);
        while((file = readdir(newdirectory))){
            if( file->d_name[0] != '.' ) {
                char buffer[4095];
                sprintf(buffer, "%s/%s", directory, file->d_name);
                set_permissions_user(buffer, uid, gid, exclusions, dirmode, filemode, filemodes);
            }
        }
    }
    else if(S_ISREG(fileStat.st_mode)){
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        FilemodeResult rFilemode = getMimeMap(filemodes, get_filename_ext(directory));
        if(rFilemode.result != -1){
            result = chmod(directory, rFilemode.filemode);
        } else {
            result = chmod(directory, filemode);
        }       
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        file_counter = file_counter + 1;
        printf("File %s permissions updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
    }
    return 0;
}

int set_permissions_user_root(char* directory, int uid, int gid, int auid, int agid, ExclusionsMap* exclusions, mode_t dirmode, mode_t filemode, MimeMap* filemodes){
    if(getExclusionsKeyPair(exclusions, directory) != -1){return 0;}
    struct stat fileStat;
    if(stat(directory, &fileStat) < 0){return 1;}
    gid_t egid = gid;
    gid_t aegid = agid;

    int result;
    if(S_ISDIR(fileStat.st_mode)){
        // Ensures that directories can always be listed by the group using ls command.
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, dirmode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        directory_counter = directory_counter + 1;
        printf("Directory %s updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
        
        DIR *newdirectory;
        struct dirent *file;
        newdirectory = opendir(directory);
        while((file = readdir(newdirectory)))
        {
            if( file->d_name[0] != '.' )
            {
                char buffer[4095];
                sprintf(buffer, "%s/%s", directory, file->d_name);
                set_permissions_user_root(buffer, uid, gid, auid, agid, exclusions, dirmode, filemode, filemodes);
            }
        }

        result = chown(directory, auid, aegid);
    }
    else if(S_ISREG(fileStat.st_mode)){
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        FilemodeResult rFilemode = getMimeMap(filemodes, get_filename_ext(directory));
        if(rFilemode.result != -1){
            result = chmod(directory, rFilemode.filemode);
        } else {
            result = chmod(directory, filemode);
        }
        result = chown(directory, auid, aegid);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        file_counter = file_counter + 1;
        printf("File %s permissions updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
    }
    return 0;
}


int breakpoint_chmod_user_root(char* directory, int uid, int gid, int auid, int agid, ExclusionsMap* exclusions, mode_t dirmode, mode_t filemode, MimeMap* filemodes){
    if(getExclusionsKeyPair(exclusions, directory) != -1){return 0;}
    struct stat fileStat;
    if(stat(directory, &fileStat) < 0){return 1;}
    gid_t egid = gid;
    gid_t aegid = agid;

    int result;
    if(S_ISDIR(fileStat.st_mode)){
        // Ensures that directories can always be listed by the group using ls command.
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, dirmode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        directory_counter = directory_counter + 1;
        printf("Directory %s updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
        
    } else if(S_ISREG(fileStat.st_mode)){
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        FilemodeResult rFilemode = getMimeMap(filemodes, get_filename_ext(directory));
        if(rFilemode.result != -1){
            result = chmod(directory, rFilemode.filemode);
        } else {
            result = chmod(directory, filemode);
        }
        result = chown(directory, auid, aegid);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        file_counter = file_counter + 1;
        printf("File %s permissions updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
    }
    return 0;
}

int set_permissions_user_root_breakpoint(char* directory, int uid, int gid, int auid, int agid, ExclusionsMap* exclusions, mode_t dirmode, mode_t filemode, MimeMap* filemodes){
    
    struct stat fileStat;
    if(stat(directory, &fileStat) < 0){return 1;}
    gid_t egid = gid;
    gid_t aegid = agid;

    int result;
    if(S_ISDIR(fileStat.st_mode)){
        // Ensures that directories can always be listed by the group using ls command.
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, dirmode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        directory_counter = directory_counter + 1;
        printf("Directory %s updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
        
        DIR *newdirectory;
        struct dirent *file;
        newdirectory = opendir(directory);
        while((file = readdir(newdirectory)))
        {
            if( file->d_name[0] != '.' )
            {
                char buffer[4095];
                sprintf(buffer, "%s/%s", directory, file->d_name);
                breakpoint_chmod_user_root(buffer, uid, gid, auid, agid, exclusions, dirmode, filemode, filemodes);
            }
        }

        result = chown(directory, auid, aegid);
    }
    else if(S_ISREG(fileStat.st_mode)){
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        FilemodeResult rFilemode = getMimeMap(filemodes, get_filename_ext(directory));
        if(rFilemode.result != -1){
            result = chmod(directory, rFilemode.filemode);
        } else {
            result = chmod(directory, filemode);
        }
        result = chown(directory, auid, aegid);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        file_counter = file_counter + 1;
        printf("File %s permissions updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
    } return 0;
}

int set_permissions_user_not_process_owner(char* directory, int uid, int gid,
    int auid, int agid, ExclusionsMap* exclusions, mode_t dirmode, mode_t filemode, MimeMap* filemodes, char* environment_type, char* exclude_files) {

    if (strcmp(environment_type, "small") == 0) {
        return set_permissions_user_not_process_owner_stack(directory, uid, gid, auid, agid, exclusions, dirmode, filemode, filemodes);
    } else {
        return set_permissions_user_not_process_owner_recursive(directory, uid, gid, auid, agid, exclusions, dirmode, filemode, filemodes, exclude_files);
    }
}

int set_permissions_user_not_process_owner_recursive(char* directory, int uid, int gid,
    int auid, int agid, ExclusionsMap* exclusions, mode_t dirmode, mode_t filemode, MimeMap* filemodes, char* exclude_files) {

    if(getExclusionsKeyPair(exclusions, directory) != -1){return 0;}
    struct stat fileStat;
    if(stat(directory, &fileStat) < 0){return 1;}
    gid_t egid = gid;
    gid_t aegid = agid;

    int result;
    if(S_ISDIR(fileStat.st_mode)){
        // Ensures that directories can always be listed by the group using ls command.
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, dirmode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)
            return 1;
        directory_counter = directory_counter + 1;
        printf("Directory %s updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);

        DIR *newdirectory;
        struct dirent *file;
        newdirectory = opendir(directory);
//       TORF-725919 - ignore the . and .. directory listings.
        while((file = readdir(newdirectory)))
        {
            if( strcmp(file->d_name, ".") != 0 && strcmp(file->d_name, "..") != 0 )
            {
                char buffer[4095];
                sprintf(buffer, "%s/%s", directory, file->d_name);
                set_permissions_user_not_process_owner_recursive(buffer, uid, gid, auid, agid, exclusions, dirmode, filemode, filemodes, exclude_files);
            }
        }
        result = chown(directory, auid, aegid);
    }
    else if(S_ISREG(fileStat.st_mode) && strcmp(exclude_files, "False") == 0){
        result = chown(directory, uid, egid);
        printf("file %s\n", directory);
        printf("Result of chown command %d\n", result);
        FilemodeResult rFilemode = getMimeMap(filemodes, get_filename_ext(directory));
        if(rFilemode.result != -1){
            printf("rFile permissions being set:");
            print_mode_permissions(rFilemode.filemode);
            result = chmod(directory, rFilemode.filemode);
        } else {
            printf("File permissions being set:");
            print_mode_permissions(filemode);
            result = chmod(directory, filemode);
        }
        result = chown(directory, auid, aegid);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)
            return 1;
        file_counter = file_counter + 1;
        printf("File %s permissions updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
    }
    return 0;
}

int set_permissions_user_not_process_owner_stack(char* directory, int uid, int gid,
    int auid, int agid, ExclusionsMap* exclusions, mode_t dirmode, mode_t filemode, MimeMap* filemodes) {

    int capacity = 1024, stackSize = 0;
    PathStackItem* stack = malloc(sizeof(PathStackItem) * capacity);
    if (!stack) {
        printf("Failed to allocate memory for stack\n");
        return -1;
    }

    PathStackItem rootItem;
    strncpy(rootItem.path, directory, PATH_MAX-1);
    rootItem.path[PATH_MAX-1] = '\0';
    push(&stack, &stackSize, &capacity, rootItem);

    while (stackSize > 0) {
        PathStackItem currentItem = pop(&stack, &stackSize);

        if(getExclusionsKeyPair(exclusions, currentItem.path) != -1) continue;

        struct stat fileStat;
        if(stat(currentItem.path, &fileStat) < 0) continue;

        int result = chown(currentItem.path, uid, gid);
        printf("Result of chown command %d\n", result);

        mode_t currentMode = S_ISDIR(fileStat.st_mode) ? dirmode : filemode;
        if (S_ISREG(fileStat.st_mode)) {
            FilemodeResult rFilemode = getMimeMap(filemodes, get_filename_ext(currentItem.path));
            currentMode = (rFilemode.result != -1) ? rFilemode.filemode : filemode;
        }

        result = chmod(currentItem.path, currentMode);
        printf("Result of chmod command %d\n", result);

        result = chown(currentItem.path, auid, agid);

        if (S_ISDIR(fileStat.st_mode)) {
            DIR* dir = opendir(currentItem.path);
            if (dir) {
                struct dirent* entry;
                while ((entry = readdir(dir)) != NULL) {
                    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

                    PathStackItem newItem;
                    snprintf(newItem.path, PATH_MAX, "%s/%s", currentItem.path, entry->d_name);
                    push(&stack, &stackSize, &capacity, newItem);
                }
                closedir(dir);
            }
        }
    }

    free(stack);
    return 0;
}

int breakpoint_chmod_user_not_process_owner(char* directory, int uid, int gid, int auid, int agid, ExclusionsMap* exclusions, mode_t dirmode, mode_t filemode, MimeMap* filemodes){
    if(getExclusionsKeyPair(exclusions, directory) != -1){return 0;}
    struct stat fileStat;
    if(stat(directory, &fileStat) < 0){return 1;}
    gid_t egid = gid;
    gid_t aegid = agid;

    int result;
    if(S_ISDIR(fileStat.st_mode)){
        // Ensures that directories can always be listed by the group using ls command.
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, dirmode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        directory_counter = directory_counter + 1;
        printf("Directory %s updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
        
    } else if(S_ISREG(fileStat.st_mode)){
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        FilemodeResult rFilemode = getMimeMap(filemodes, get_filename_ext(directory));
        if(rFilemode.result != -1){
            result = chmod(directory, rFilemode.filemode);
        } else {
            result = chmod(directory, filemode);
        }
        result = chown(directory, auid, aegid);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        file_counter = file_counter + 1;
        printf("File %s permissions updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
    }
    return 0;
}

int set_permissions_user_not_process_owner_breakpoint(char* directory, int uid, int gid, 
    int auid, int agid, ExclusionsMap* exclusions, mode_t dirmode, mode_t filemode, MimeMap* filemodes) {
    
    struct stat fileStat;
    if(stat(directory, &fileStat) < 0){return 1;}
    gid_t egid = gid;
    gid_t aegid = agid;

    int result;
    if(S_ISDIR(fileStat.st_mode)){
        // Ensures that directories can always be listed by the group using ls command.
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        result = chmod(directory, dirmode);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        directory_counter = directory_counter + 1;
        printf("Directory %s updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
        DIR *newdirectory;
        struct dirent *file;
        newdirectory = opendir(directory);
        while((file = readdir(newdirectory)))
        {
            if( file->d_name[0] != '.' )
            {
                char buffer[4095];
                sprintf(buffer, "%s/%s", directory, file->d_name);
                breakpoint_chmod_user_not_process_owner(buffer, uid, gid, auid, agid, exclusions, dirmode, filemode, filemodes);
            }
        }
        result = chown(directory, auid, aegid);
    }
    else if(S_ISREG(fileStat.st_mode)){
        result = chown(directory, uid, egid);
        printf("directory %s\n", directory);
        printf("Result of chown command %d\n", result);
        FilemodeResult rFilemode = getMimeMap(filemodes, get_filename_ext(directory));
        if(rFilemode.result != -1){
            result = chmod(directory, rFilemode.filemode);
        } else {
            result = chmod(directory, filemode);
        }
        result = chown(directory, auid, aegid);
        printf("Result of chmod command %d\n", result);
        if(stat(directory, &fileStat) < 0)    
            return 1;
        file_counter = file_counter + 1;
        printf("File %s permissions updated to \n", directory);
        print_mode_permissions(fileStat.st_mode);
    }
    return 0;
}

int set_permissions(char* directory, char* dirmode, char* filemode, char* file_ext_pemissions,
     int uid_to_set, int gid_to_set, char* breakpoints, char* exclusion, char* environment_type, char* exclude_files) {
    /**
     * @param directory The directory to change the permissions of.
     * @param dirmode The directory mode to use
     * @param filemode The filemode to use
     * @param file_ext_permissions A list of file permissions as extension,permission pairs e.g. "xml,660,sh,550,txt,400"
     * @param uid_to_set The UID specified in mapping xml/yaml to update the file to.
     * @param git_to_set The GID specified in mapping xml/yaml to update the file to.
     * @param breakpoints A comma separated list of directory breakpoints
     * @param exclusion The full path of the files to exclude as a , separated list
     */

    uid_t uid = getuid(); // Gets the uid of the user running the process
    gid_t gid = getgid(); // Gets the gid of the user running the process
    uid_t auid = uid_to_set; //convert to ints to uid_t struct
    gid_t agid = gid_to_set;

    
    mode_t afilemode = permissions_string_to_file_mode(filemode);
    mode_t adirmode = permissions_string_to_file_mode(dirmode);
    printf("\nExclusion \n");
    printf("%s\n", directory);
    printf("%s\n", exclusion);
    printf("%s\n", dirmode);
    printf("dirmode: ");
    print_mode_permissions(adirmode);
    printf("%s\n", file_ext_pemissions);
    
    ExclusionsMap* exclusions = exclusionsSplit(exclusion, ',');
    MimeMap* filemodes = mimeSplit(file_ext_pemissions,',');
    if (!(adirmode & S_IXUSR) || !(adirmode & S_IXGRP)) {
        adirmode = adirmode | S_IXGRP;
        adirmode = adirmode | S_IXUSR;
    }
    struct splitString splitBreakpoints = split(breakpoints, ',');
    int breakpointCounter = 0;
    while (breakpointCounter < splitBreakpoints.length){
        printf("%s ", splitBreakpoints.array[breakpointCounter]);
        setExclusionKeyPair(exclusions, splitBreakpoints.array[breakpointCounter], true);
        breakpointCounter = breakpointCounter + 1;
    }
    
    
    int res;
    breakpointCounter = 0;
    res = set_permissions_user_not_process_owner(directory, uid, gid, auid, agid, exclusions, adirmode, afilemode, filemodes, environment_type, exclude_files);
    while (breakpointCounter < splitBreakpoints.length) {
        res = res + set_permissions_user_not_process_owner_breakpoint(
                splitBreakpoints.array[breakpointCounter], 
                uid, gid, auid, agid, exclusions, adirmode, afilemode, filemodes
            );
        breakpointCounter = breakpointCounter + 1;
    } return res;
    
    printf("Number of directory permissions updated %d \n", directory_counter);
    printf("Number of file permissions updated %d \n", file_counter);
    return res;
}

int run_chown(char* directory, int uid_to_set, int gid_to_set){
    chown(directory, uid_to_set, gid_to_set);
}

