# trivy-exporter
Run scanners on local FS and all docker containers running on a machine then produce metrics identical to those of the official trivy operator.

## Build and test docker image

```
docker build -t trivy-exporter .
docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock:ro -v /:/rootfs:ro -v ./data:/webapp/data -p 9000:9000 trivy-exporter
```