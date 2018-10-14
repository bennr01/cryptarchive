# create a container from the image
sudo docker build -t cryptarchive-server:latest --no-cache . &&
sudo docker container stop cryptarchive-server;
sudo docker container rm cryptarchive-server;
sudo docker container create --volume /server/data/cryptarchive/:/data/ --name cryptarchive-server --publish 45654:45654 cryptarchive-server &&
sudo docker container start cryptarchive-server
echo "Done."
