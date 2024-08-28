def allow_ls_on_dir(parent_directory):
    x = "/home/lciadm100/evadtam/nonroot/eric-enm-permissions-mgr/rpm/src"
    x=x.replace(parent_directory,"")
    x = x.split("/")
    if x[0] == "":
        x=x[1:]
    current_working_directory = parent_directory
    for directory in x:
        current_working_directory = current_working_directory + "/" + directory
        print(current_working_directory)

allow_ls_on_dir("/home/lciadm100")