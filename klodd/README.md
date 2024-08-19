# Deploying klodd
## GKE
```bash
gcloud config set project idekctf-374221
gcloud container clusters create --release-channel regular --zone us-east4-b --enable-network-policy --enable-autoscaling \
    --min-nodes 1 --max-nodes 2 --num-nodes 1 --no-enable-master-authorized-networks --enable-autorepair --preemptible \
    --machine-type e2-standard-2 klodd-cluster
gcloud container clusters get-credentials klodd-cluster --zone us-east4-b

gcloud compute addresses create klodd-ip --region us-east4
```

## Lets Encrypt
```
sudo certbot certonly --manual --preferred-challenges=dns --email stepan.fedotov@gmail.com --agree-tos -d instancer.idek.team,*.instancer.idek.team
sudo cp /etc/letsencrypt/live/instancer.idek.team/{fullchain.pem,privkey.pem} certs && sudo chown $(whoami):$(whoami) certs/*.pem
```

Update 00-traefik.yaml with the certs.

## Apply everything

Apply all the manifests in k8s/ in their respective order.