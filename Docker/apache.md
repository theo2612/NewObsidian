quick, temporary apache text
Terminal 1:
docker run --rm -it -p 8080:80 ubuntu/apache2:latest

Terminal 2:
curl localhost:8080
there's an example of running apache2 on another port btw

<host_ip>:<host_port>:<container_port>


```basj
$ vim index.html
```
From html directory on host, 
create an index.html file or any other file name
and put text in it
```bash
$ docker run --rm -d --namne apache -p 8080:80 -v .:/var/www/html ubuntu/apache2:latest
```
- `docker run`: tells Docker to run a container.
- `--rm`:  container should be automatically removed when it stops. 
- `-d`: stands for "detached," which means the container runs in the background.
- `--name apache`: It assigns the name "apache" to the container.
- `-p 8080:80`: This flag maps port 8080 on your host machine to port 80 in the container, so you can access the web server at [http://localhost:8080](http://localhost:8080).
- `-v $(pwd)/html:/var/www/html`: This maps a volume from your current directory's "html" folder to the "/var/www/html" folder in the container. You can use this to serve web content.
- `ubuntu/apache2:latest`: This is the name of the Docker image you're using, which is based on Ubuntu and contains Apache2.



