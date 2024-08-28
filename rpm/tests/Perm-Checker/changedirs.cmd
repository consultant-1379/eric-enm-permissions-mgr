# Change permissions
chmod 00755 /ericsson/netlog/export
chmod 00755 /ericsson/tor/no_rollback/fmexport/data
chmod 00755 /ericsson/config_mgt/ebnfToJson
chmod 00755 /ericsson/configuration_management/UpgradeIndependence/add_support
mkdir -p /ericsson/enm/dumps/fmx
chmod 00755 /ericsson/enm/dumps/fmx
chmod 00755 /ericsson/pmic1/fls_file_already_exist
chmod 00755 /ericsson/tor/data/apps/cliapp
chmod 00750 /ericsson/tor/no_rollback/fmexport
chmod 00750 /ericsson/tor/no_rollback/fmexport/data
# Change owners
chown root:root /ericsson/tor/no_rollback/fmexport
chown root:206 /ericsson/tor/no_rollback/fmexport/data
chown root:root /ericsson/tor/data/apps/cliapp
chown 308:root /ericsson/enm/dumps/fmx
# Change files.
chmod 440 /ericsson/tor/data/fmx/export/GRX*
chown root:root /ericsson/tor/data/fmx/export/GRX*
# This one seems to be -r--r--- in some delpoyments but permission-mgr rwxrwx
chmod 777 /ericsson/tor/data/nbi/fm/bnsi/dummy
# Test .files - these will create as root:root
touch /ericsson/configuration_management/UpgradeIndependence/workdir/.data.txt
#touch /ericsson/netlog/export/.data.txt
touch /ericsson/netlog/radionode/.data.txt
touch /ericsson/pmic1/fls_file_already_exist/.fls_file_already_exist
touch /ericsson/tor/no_rollback/fmexport/data/.data.data
# change permissions as well
chmod 700 /ericsson/configuration_management/UpgradeIndependence/workdir/.data.txt
#chmod 700 /ericsson/netlog/export/.data.txt
chmod 700 /ericsson/netlog/radionode/.data.txt
chmod 700 /ericsson/pmic1/fls_file_already_exist/.fls_file_already_exist
chmod 700 /ericsson/tor/no_rollback/fmexport/data/.data.data
chown root /ericsson/configuration_management/UpgradeIndependence/workdir/.data.txt
#chown root /ericsson/netlog/export/.data.txt
chown root /ericsson/netlog/radionode/.data.txt
chown root /ericsson/pmic1/fls_file_already_exist/.fls_file_already_exist
chown root /ericsson/tor/no_rollback/fmexport/data/.data.data
# Prove files got created ok
echo -e "Verify files got created"
ls -la /ericsson/configuration_management/UpgradeIndependence/workdir/.data.txt
#ls -la /ericsson/netlog/export/.data.txt
ls -la /ericsson/netlog/radionode/.data.txt
ls -la /ericsson/pmic1/fls_file_already_exist/.fls_file_already_exist
ls -la /ericsson/tor/no_rollback/fmexport/data/.data.data
# Delete directories
rm -rf /ericsson/batch/undo
rm -rf /ericsson/batch/data
rm -rf /ericsson/tor/data/fmx/moduleserver/repos
rm -rf /ericsson/configuration_management/UpgradeIndependence/node_models
# Prove directories were deleted
echo -e "Verify directories were deleted "
ls -ld /ericsson/batch/undo
ls -ld /ericsson/batch/data
ls -ld /ericsson/tor/data/fmx/moduleserver/repos
ls -ld /ericsson/configuration_management/UpgradeIndependence/node_models
# Check large filename 
touch /ericsson/config_mgt/import_files/1707381967189__tmp_wl_storage_profile_undo_configs_cmimport_03_default_PZcVUIcLCYUEdfGZUWTRBPacTTVIHDAundo_2024-02-08T09-45-04_503.txt
