- _Images_ - The blueprints of our application which form the basis of containers. In the demo above, we used the `docker pull` command to download the **busybox** image.
- _Containers_ - Created from Docker images and run the actual application. We create a container using `docker run` which we did using the busybox image that we downloaded. A list of running containers can be seen using the `docker ps` command.
- _Docker Daemon_ - The background service running on the host that manages building, running and distributing Docker containers. The daemon is the process that runs in the operating system which clients talk to.
- _Docker Client_ - The command line tool that allows the user to interact with the daemon. More generally, there can be other forms of clients too - such as [Kitematic](https://kitematic.com/) which provide a GUI to the users.
- _Docker Hub_ - A [registry](https://hub.docker.com/explore/) of Docker images. You can think of the registry as a directory of all available Docker images. If required, one can host their own Docker registries and can use them for pulling images.

view docker image info, where stored, network config
```bash
$ docker inspect busy_hertz
```

view docker containers running and stopped
```bash
$ docker container ls -a
```

spin up a ubuntu docker container 
```bash
$ docker run -it ubuntu bash
```

install ip addr
```bash
$ apt update && apt install -y iproute2 && ip addr
```

ascii art dancing parrot
```bash
sudo docker run -it --rm jmhobbs/terminal-parrot:latest
```

list running containers
```bash
$ docker ps
```

runs the docker container with -it command that opens a tty shell
```bash
$ docker run -it busybox sh
```

multiple containers to delete in one go?
```bash
$ docker rm $(docker ps -a -q -f status=exited)
```

similar to docker rm
```bash
$ docker container prune
WARNING! This will remove all stopped containers.
Are you sure you want to continue? [y/N] y
Deleted Containers:
4a7f7eebae0f63178aff7eb0aa39f0627a203ab2df258c1a00b456cf20063
f98f9c2aa1eaf727e4ec9c0283bcaa4762fbdba7f26191f26c97f64090360

Total reclaimed space: 212 B
```



