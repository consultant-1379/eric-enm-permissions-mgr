#check permissions
ls -ld /ericsson/netlog/export
ls -ld /ericsson/tor/no_rollback/fmexport/data
ls -ld /ericsson/config_mgt/ebnfToJson
ls -ld /ericsson/configuration_management/UpgradeIndependence/add_support
ls -ld /ericsson/enm/dumps/fmx
ls -ld /ericsson/pmic1/fls_file_already_exist
ls -ld /ericsson/tor/data/apps/cliapp
ls -ld /ericsson/tor/no_rollback/fmexport
ls -ld /ericsson/tor/no_rollback/fmexport/data
#check owners
#ls -ld /ericsson/tor/no_rollback/fmexport
#ls -ld /ericsson/tor/no_rollback/fmexport/data
#ls -ld /ericsson/tor/data/apps/cliapp
#ls -ld /ericsson/enm/dumps/fmx
# check files.
ls -ld /ericsson/tor/data/fmx/export/GRX*
# This one seems to be -r--r--- in some deployments but perm manage rwxrwx
ls -ld /ericsson/tor/data/nbi/fm/bnsi/dummy
ls -ld /ericsson/enm/dumps/fmx
# Test .files - these were created as root:root
#ls -la /ericsson/netlog/export/.data.txt
ls -la /ericsson/configuration_management/UpgradeIndependence/workdir/.data.txt
ls -la /ericsson/netlog/radionode/.data.txt
ls -la /ericsson/pmic1/fls_file_already_exist/.fls_file_already_exist
ls -la /ericsson/tor/no_rollback/fmexport/data/.data.data
# Check the deleted are back
ls -ld /ericsson/batch/undo
ls -ld /ericsson/batch/data
ls -ld /ericsson/tor/data/fmx/moduleserver/repos
ls -ld /ericsson/configuration_management/UpgradeIndependence/node_models
# Check strange files
ls -la /ericsson/config_mgt/import_files/1707381967189__tmp_wl_storage_profile_undo_configs_cmimport_03_default_PZcVUIcLCYUEdfGZUWTRBPacTTVIHDAundo_2024-02-08T09-45-04_503.txt
