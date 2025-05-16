# Individual Assignment: DATA2410 Reliable Transport Protocol (DRTP)
## Instructions on how to run application.py

First of all, simpletopo.py must be run as root on mininet, in the same folder as the project:
```
python3 simpletopo.py
```
Next, use `xterm` to open `h1` and `h2` terminals. Now, `application.py` can must be run as server on `h2` and client on `h1`.

An example of how to run the server:
```
python3 application.py -s -i <ip_address_of_the_server> -p <port>
```

The client can be run as follows:
```
python3 application.py -c  -f Photo.jpg -i <ip_address_of_the_server> -p <server_port> -w <window_size>
```

You might need to check the ip address you want to use on the server side by doing `h2 ifconfig` in mininet before running the application. The same ip should be used on the client side, for example:

```
python3 application.py -s -i 10.0.1.2 -p 8000

python3 application.py -c -f iceland-safiqul.jpg -i 10.0.1.2 -p 8000 -w 5
```

These are the options that you can use to invoke the server or client:

| flag | long flag | input | type | Description |
|------|-----------|-------|------|-------------|
| -s | --server  |   X   | bool | run as server |
| -c | --client  | X     | bool | run as client |
| -i | --ip | ip address | string | allows to bind the ip address at the server side. The client will use this flag to select server's ip for the connection - use a default value if it's not provided. It must be in the dotted decimal notation format, e.g. 10.0.1.2 |
| -p | --port | port number | int | allows to use select port number on which the server should listen and at the client side, it allows to select the server's port number; the port must be an integer and in the range [1024, 65535], default: 8088
| -f | --file | x | string | allows you to choose the jpg file |
| - w | --window | x | int | sliding window size, default: 3 |
| -d | --discard | x | int | a custom test case to skip a seq to check for retransmission. If you pass -d 11 on the server side, your server will discard packet with seq number 11 only for once. Make sure you change the value to an infinitely large number after your first check in order to avoid skipping seq=11 all the time. |

The discard flag can be used on the server side like this:
```
python3 application.py -s -i 10.0.1.2 -p 8080 -d 8
```
 - this discards the 8th packet