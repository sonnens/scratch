#!/bin/bash
set -o xtrace

#need OLD_HN NEW_HN OLD_CLOUDAPI NEW_CLOUDAPI

SSH="ssh"
ID="-i /root/.ssh/id_rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
LOCALID="-i $HOME/.ssh/id_rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

function curl_sig() {
  if [[ -z $CLOUDAPI_USER ]]; then
    CLOUDAPI_USER="admin"
  fi
  local now=`date -u "+%a, %d %h %Y %H:%M:%S GMT"` ;
  local signature=`echo ${now} | tr -d '\n' | openssl dgst -sha256 -sign ~/.ssh/id_rsa | openssl enc -e -a | tr -d '\n'` ;
  local keyid=`ssh-keygen -lf ~/.ssh/id_rsa.pub | cut -d ' ' -f 2`
  curl -k -s -H "Accept: application/json" -H "x-api-version: ~6.5" -H "Content-type: application/json" \
    -H "Date: ${now}" \
    -H "Authorization: Signature keyId=\"/${CLOUDAPI_USER}/keys/${keyid}\",algorithm=\"rsa-sha256\" ${signature}" \
    --url $@ ;
  echo "";
}
function curl_sig7() {
  if [[ -z $CLOUDAPI_USER ]]; then
    CLOUDAPI_USER="admin"
  fi
  local now=`date -u "+%a, %d %h %Y %H:%M:%S GMT"` ;
  local signature=`echo ${now} | tr -d '\n' | openssl dgst -sha256 -sign ~/.ssh/id_rsa | openssl enc -e -a | tr -d '\n'` ;
  local keyid=`ssh-keygen -lf ~/.ssh/id_rsa.pub | cut -d ' ' -f 2`
  curl -k -s -H "Accept: application/json" -H "x-api-version: ~7.0" -H "Content-type: application/json" \
    -H "Date: ${now}" \
    -H "Authorization: Signature keyId=\"/${CLOUDAPI_USER}/keys/${keyid}\",algorithm=\"rsa-sha256\" ${signature}" \
    --url $@ ;
  echo "";
}

src_users=$($SSH $LOCALID ${OLD_HN} "/smartdc/bin/sdc-capi /customers" | json -H -a login)
for user in $src_users; do
if [[ -z $(curl_sig7 ${NEW_CLOUDAPI}/${user} | json -H | grep id) ]]; then
  continue
fi
old_machines=$(curl_sig ${OLD_CLOUDAPI}/${user}/machines)
for i in $(seq 0 $((`echo $old_machines | json length` - 1))); do
  old_dataset=$(echo $old_machines | \
      json ${i}.dataset | \
      cut -d ':' -f 3 | \
      sed -e 's:engine-:engine:g' | \
      sed -e 's:engine6.4.2:engine-6.4.4:g' | \
      sed -e 's:smartosplus:base64:g')
  new_dataset=$(curl_sig7 ${NEW_CLOUDAPI}/${user}/images | \
    json -c "this.name == \"${old_dataset}\"" | json 0.id);
  if [[ -z $new_dataset ]]; then
    echo "Could not find dataset for vm:  $(echo $old_machines | json ${i}.name), looking for $old_dataset"
    continue
  fi
  new_package=""

  mem=$(echo $old_machines | json ${i}.memory)
  disk=$(echo $old_machines | json ${i}.disk)
  name=$(echo $old_machines | json ${i}.name)
  old_id=$(echo $old_machines | json ${i}.id)

  networks=$(curl_sig7 ${NEW_CLOUDAPI}/${user}/networks | json -c "this.name == \"external\"" | json 0.id)
  if [[ $(echo $old_machines | json ${i}.type) == 'virtualmachine' ]]; then
    new_package=$(curl_sig7 ${NEW_CLOUDAPI}/${user}/packages | json -c "this.memory >= ${mem} && this.vcpus != 0 && this.disk >= ${disk}" | json 0.id)
  else
    new_package=$(curl_sig7 ${NEW_CLOUDAPI}/${user}/packages | json -c "this.memory >= ${mem} && this.vcpus == 0 && this.disk >= ${disk}" | json 0.id)
  fi
  new_machine_spec=$(echo '{}' | json -e "this.package = \"${new_package}\"" | json -e "this.image = \"${new_dataset}\"" | json -e "this.networks = [\"${networks}\"]" | json -e "this.name = \"${name}\"") 
  new_machine=$(echo $new_machine_spec | curl_sig7 ${NEW_CLOUDAPI}/${user}/machines -X POST -d@-)
  new_id=$(echo $new_machine | json id)
  echo "${name}:${old_id}:${new_id}" >> log.txt

  sleep 5 # yay cloudapi.
  state=$(echo $new_machine | json state)
  sentinel=120
  while [[ ${state} == "provisioning" ]]; do
    sleep 2
    state=$(curl_sig7 ${NEW_CLOUDAPI}/${user}/machines/${new_id} | json state)
    sentinel=$(($sentinel - 1))
    if [[ $sentinel < 1 ]]; then
      break
    fi
  done
  if [[ "${state}" != "running" ]]; then
    echo "Problem provisioning ${name} (${old_id}) to ${new_id}"
    continue
  fi

  curl_sig7 ${NEW_CLOUDAPI}/${user}/machines/${new_id}?action=stop -X POST

  state=$(curl_sig7 ${NEW_CLOUDAPI}/${user}/machines/${new_id} | json state)
  sentinel=120
  while [[ ${state} == "running" || ${state} == "stopping" ]]; do
    sleep 2
    state=$(curl_sig7 ${NEW_CLOUDAPI}/${user}/machines/${new_id} | json state)
    sentinel=$(($sentinel - 1))
    if [[ $sentinel < 1 ]]; then
      break
    fi
  done;

  if [[ "${state}" != "stopped" ]]; then
    echo "Problem stopping ${name} (${new_id})"
    continue
  fi
  if [[ $(echo $old_machines | json ${i}.type) == 'virtualmachine' ]]; then
    dataset_suffix="-disk0"
    old_cn=$($SSH $LOCALID $OLD_HN "/smartdc/bin/sdc-mapi /vms/${old_id}" | json -H server.ip_address)
  else
    dataset_suffix=""
    old_server=$($SSH $LOCALID $OLD_HN "/smartdc/bin/sdc-mapi /zones/${old_id}" | json -H server_id)
    old_cn=$($SSH $LOCALID $OLD_HN "/smartdc/bin/sdc-mapi /servers/${old_server}" | json -H ip_address) 
  fi

  new_server=$($SSH $LOCALID $NEW_HN "/opt/smartdc/bin/sdc-vmapi /vms/${new_id}" | json -H server_uuid)
  new_cn=$($SSH $LOCALID $NEW_HN "/opt/smartdc/bin/sdc-cnapi /servers/${new_server}" | grep ip4addr | grep -v '""' | cut -d ':' -f 2 | tr -d '"' | tr -d ' ' | tr -d ',')

  if [[ -z ${new_id} ]]; then
    exit 1
  fi
  # horrible amounts of escape sequences
  $SSH $LOCALID $NEW_HN "$SSH $ID ${new_cn} \"zfs umount /zones/${new_id}/cores && zfs destroy -F zones/${new_id}${dataset_suffix}\""
  ($SSH $LOCALID $OLD_HN "$SSH $ID ${old_cn} \"zfs snapshot zones/${old_id}${dataset_suffix}@export\"" || /bin/true)
  echo "Sending zones/${old_id}${dataset_suffix}@export from ${old_cn} to ${new_cn} as zones/${new_id}${dataset_suffix}@recv"
  $SSH $LOCALID $NEW_HN <<eof
$SSH $ID $OLD_HN "$SSH $ID ${old_cn} \"zfs send zones/${old_id}${dataset_suffix}@export\"" | $SSH $ID ${new_cn} "zfs recv zones/${new_id}${dataset_suffix}@recv"
eof
  done;
done
