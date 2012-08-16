/*
 * Copyright (C) 2009-2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "git2/net.h"
#include "git2/common.h"
#include "git2/types.h"
#include "git2/errors.h"
#include "git2/net.h"
#include "git2/revwalk.h"
#include "git2/ssh.h"

#include "vector.h"
#include "transport.h"
#include "pkt.h"
#include "common.h"
#include "netops.h"
#include "filebuf.h"
#include "repository.h"
#include "fetch.h"
#include "protocol.h"

#define SSH_GIT_TRACE 1

typedef struct {
	git_transport parent;
	git_protocol proto;
	git_vector refs;
	git_remote_head **heads;
	git_transport_caps caps;
	char buff[1024];
	gitno_buffer buf;
#ifdef GIT_WIN32
	WSADATA wsd;
#endif
} transport_ssh;

static git_ssh_auth_type authType;
static char* sshUsername;
static char* sshPassword;
static char* sshPublicKey;
static char* sshPrivateKey;
static char* sshKeypass;

int git_ssh_auth_setup(git_ssh_auth_type  auth_type) {
	authType = auth_type;
	return 0;
}

int git_ssh_password_auth(const char* username,const char* password) {

	if (sshPassword) {
		free(sshPassword);
		sshPassword = 0;
	}
	if (sshUsername) {
		free(sshUsername);
		sshUsername = 0;
	}

	if (password) {
		sshPassword = malloc(sizeof(char)*strlen(password));
        strcpy(sshPassword, password);
	}
	if (username) {
		sshUsername = malloc(sizeof(char)*strlen(username));
		strcpy(sshUsername, username);
	}

#ifdef SSH_GIT_TRACE
	printf("setting sshUsername=%s\n",sshUsername);
	printf("setting sshPassword=%s\n",sshPassword);

#endif

	return 0;
}

int git_ssh_keyfileinfo(const char* publickey,
                                         const char* privatekey,
                                         const char* keypass) {
	if (sshPublicKey) {
		free(sshPublicKey);
		sshPublicKey = 0;
	}
	if (sshPrivateKey) {
		free(sshPrivateKey);
		sshPrivateKey = 0;
	}
	if (sshKeypass) {
		free(sshKeypass);
		sshKeypass = 0;
	}
	if (publickey) {
		sshPublicKey = malloc(sizeof(char)*strlen(publickey));
		strcpy(sshPublicKey, publickey);
	}
	if (privatekey) {
			sshPrivateKey = malloc(sizeof(char)*strlen(privatekey));
			strcpy(sshPrivateKey, privatekey);
		}
	if (keypass) {
			sshKeypass = malloc(sizeof(char)*strlen(keypass));
			strcpy(sshKeypass, keypass);
		}


	return 0;
}

void git_ssh_freeauth() {
if (sshPublicKey) {
	free(sshPublicKey);
	sshPublicKey = 0;
}
if (sshPrivateKey) {
	free(sshPrivateKey);
	sshPrivateKey = 0;
}
if (sshKeypass) {
	free(sshKeypass);
	sshKeypass = 0;
}
if (sshPassword) {
	free(sshPassword);
	sshPassword = 0;
}
if (sshUsername) {
	free(sshUsername);
	sshUsername = 0;
}
}

/*
 * Create a git ssh protocol request.
 *
 * For example: git-upload-pack /libgit2/libgit2
 */
static int ssh_proto(git_buf *request, const char *cmd, const char *url)
{
	char *delim, *repo;
	char default_command[] = "git-upload-pack";
	//char host[] = "host=";
	size_t len;

	delim = strchr(url, ':');

	if (delim == NULL) {
		delim = strchr(url,'/');
		if (delim == NULL) {
			giterr_set(GITERR_NET, "Malformed URL");
			return -1;
		}
	} else {
		delim = delim++;
	}

	repo = delim;


	if (cmd == NULL)
		cmd = default_command;

	len = strlen(cmd) + 1 + strlen(repo) +1 + 2;

	git_buf_grow(request, len);
	git_buf_printf(request, "%s '%s'", cmd, repo);
	len = strlen(request->ptr);
	if (git_buf_oom(request))
		return -1;

	return 0;
}

/*
 * Send an exec to the ssh channel
 *
 *
 */
static int ssh_send_command(git_transport *t, const char *msg, size_t len,
	int flags) {
int rc;
while ((rc = libssh2_channel_exec(t->ssh.channel, msg)) == LIBSSH2_ERROR_EAGAIN)
	{
	ssh_wait(t->socket,t->ssh.session,1,0);
	}
if (rc != 0) {
	net_set_error("could not send command");
	return -1;
}
return 0;
}

static int send_request(git_transport *t, const char *cmd, const char *url)
{
	int error;
	git_buf request = GIT_BUF_INIT;

	error = ssh_proto(&request, cmd, url);
	if (error < 0)
		goto cleanup;

	//error = gitno_send(t, request.ptr, request.size, 0);
	error = ssh_send_command(t, request.ptr, request.size, 0);

cleanup:
	git_buf_free(&request);
	return error;
}



/*
 * Parse the URL and connect to a server, storing the socket in
 * out. For convenience this also takes care of asking for the remote
 * refs
 */
static int do_connect(transport_ssh *t, const char *url)
{

#ifdef SSH_GIT_TRACE
    printf("1sshUsername=%s\n",sshUsername);
    printf("1sshPassword=%s\n",sshPassword);

#endif

    char *host, *port,*username;
	const char prefix[] = "git+ssh://";
	const char prefix2[] = "ssh+git://";
	const char prefix3[] = "ssh://";
	const char sshstyle[] = "://";
	int sshurl = 0;

	if (!strstr(url,sshstyle)) {
		sshurl = 1;
	}

	if (!git__prefixcmp(url, prefix))
		url += strlen(prefix);

	if (!git__prefixcmp(url, prefix2))
			url += strlen(prefix2);

	if (!git__prefixcmp(url, prefix3))
			url += strlen(prefix3);

	username = 0;
	char *u = strstr(url,"@");
	if (u) {
		// points to end of username
		username = git__strndup(url,(u-url));
		url = u+1;
	}
	t->parent.ssh.urlusername = username;
	t->parent.ssh.sshKeypass = sshKeypass;
	t->parent.ssh.authType = authType;
	t->parent.ssh.sshPassword = sshPassword;
	t->parent.ssh.sshPrivateKey = sshPrivateKey;
	t->parent.ssh.sshPublicKey = sshPublicKey;
	t->parent.ssh.sshUsername = sshUsername;

	if (t->parent.ssh.sshUsername == NULL) {
		t->parent.ssh.sshUsername = t->parent.ssh.urlusername; // use the url username if the sshUsername isn't set manually
	}

	if (t->parent.ssh.authType == GIT_SSH_AUTH_PASSWORD && t->parent.ssh.sshPassword == NULL) {
		t->parent.ssh.sshPassword = "";
	}

#ifdef SSH_GIT_TRACE
	printf("sshUsername=%s\n",t->parent.ssh.sshUsername);
	printf("sshPassword=%s\n",t->parent.ssh.sshPassword);

#endif

	if (sshurl) {
		port = git__strdup(SSH_DEFAULT_PORT);
		char *colon = strchr(url, ':');
		host = git__strndup(url,colon-url);
	} else {
		if (gitno_extract_host_and_port(&host, &port, url, SSH_DEFAULT_PORT) < 0)
					return -1;
	}
	if (gitno_connect((git_transport *)t, host, port) < 0)
		goto on_error;

	if (send_request((git_transport *)t, NULL, url) < 0)
		goto on_error;

	//git__free(username);
	git__free(host);
	git__free(port);

	return 0;

on_error:
//	git__free(username);
	git__free(host);
	git__free(port);
	gitno_close(t->parent.socket);
	return -1;
}

/*
 * Read from the socket and store the references in the vector
 */
static int store_refs(transport_ssh *t)
{
	gitno_buffer *buf = &t->buf;
	int ret = 0;

	while (1) {
		if ((ret = gitno_recv(buf)) < 0)
			return -1;
		if (ret == 0) /* Orderly shutdown, so exit */
			return 0;

		ret = git_protocol_store_refs(&t->proto, buf->data, buf->offset);
		if (ret == GIT_EBUFS) {
			gitno_consume_n(buf, buf->len);
			continue;
		}

		if (ret < 0)
			return ret;

		gitno_consume_n(buf, buf->offset);

		if (t->proto.flush) { /* No more refs */
			t->proto.flush = 0;
			return 0;
		}
	}
}

static int detect_caps(transport_ssh *t)
{
	git_vector *refs = &t->refs;
	git_pkt_ref *pkt;
	git_transport_caps *caps = &t->caps;
	const char *ptr;

	pkt = git_vector_get(refs, 0);
	/* No refs or capabilites, odd but not a problem */
	if (pkt == NULL || pkt->type == GIT_PKT_FLUSH || pkt->capabilities == NULL)
		return 0;

	ptr = pkt->capabilities;
	while (ptr != NULL && *ptr != '\0') {
		if (*ptr == ' ')
			ptr++;

		if(!git__prefixcmp(ptr, GIT_CAP_OFS_DELTA)) {
			caps->common = caps->ofs_delta = 1;
			ptr += strlen(GIT_CAP_OFS_DELTA);
			continue;
		}

		/* We don't know this capability, so skip it */
		ptr = strchr(ptr, ' ');
	}

	return 0;
}

/*
 * Since this is a network connection, we need to parse and store the
 * pkt-lines at this stage and keep them there.
 */
static int ssh_connect(git_transport *transport, int direction)
{
	transport_ssh *t = (transport_ssh *) transport;

	if (direction == GIT_DIR_PUSH) {
		giterr_set(GITERR_NET, "Pushing over git:// is not supported");
		return -1;
	}

	t->parent.direction = direction;
	if (git_vector_init(&t->refs, 16, NULL) < 0)
		return -1;

	/* Connect and ask for the refs */
	if (do_connect(t, transport->url) < 0)
		goto cleanup;

	gitno_buffer_setup(transport, &t->buf, t->buff, sizeof(t->buff));

	t->parent.connected = 1;

	if (store_refs(t) < 0)
		goto cleanup;

	if (detect_caps(t) < 0)
		goto cleanup;

	if (&t->refs.length == 0) {
		giterr_set_str(GITERR_NET,"something went wrong, no refs from this remote");
		goto cleanup;
	}

	return 0;
cleanup:
	git_vector_free(&t->refs);
	return -1;
}

static int ssh_ls(git_transport *transport, git_headlist_cb list_cb, void *opaque)
{
	transport_ssh *t = (transport_ssh *) transport;
	git_vector *refs = &t->refs;
	unsigned int i;
	git_pkt *p = NULL;

	git_vector_foreach(refs, i, p) {
		git_pkt_ref *pkt = NULL;

		if (p->type != GIT_PKT_REF)
			continue;

		pkt = (git_pkt_ref *)p;

		if (list_cb(&pkt->head, opaque) < 0) {
			giterr_set(GITERR_NET, "User callback returned error");
			return -1;
		}
	}

	return 0;
}

/* Wait until we get an ack from the */
static int recv_pkt(gitno_buffer *buf)
{
	const char *ptr = buf->data, *line_end;
	git_pkt *pkt;
	int pkt_type, error;

	do {
		/* Wait for max. 1 second */
		if ((error = gitno_select_in(buf, 1, 0)) < 0) {
			return -1;
		} else if (error == 0) {
			/*
			 * Some servers don't respond immediately, so if this
			 * happens, we keep sending information until it
			 * answers. Pretend we received a NAK to convince higher
			 * layers to do so.
			 */
			return GIT_PKT_NAK;
		}

		if ((error = gitno_recv(buf)) < 0)
			return -1;

		error = git_pkt_parse_line(&pkt, ptr, &line_end, buf->offset);
		if (error == GIT_EBUFS)
			continue;
		if (error < 0)
			return -1;
	} while (error);

	gitno_consume(buf, line_end);
	pkt_type = pkt->type;
	git__free(pkt);

	return pkt_type;
}

static int ssh_negotiate_fetch(git_transport *transport, git_repository *repo, const git_vector *wants)
{
	transport_ssh *t = (transport_ssh *) transport;
	git_revwalk *walk;
	git_oid oid;
	int error;
	unsigned int i;
	git_buf data = GIT_BUF_INIT;
	gitno_buffer *buf = &t->buf;

	if (git_pkt_buffer_wants(wants, &t->caps, &data) < 0)
		return -1;

	if (git_fetch_setup_walk(&walk, repo) < 0)
		goto on_error;

	if (gitno_send(transport, data.ptr, data.size, 0) < 0) // send to ssh here!
		goto on_error;

	git_buf_clear(&data);
	/*
	 * We don't support any kind of ACK extensions, so the negotiation
	 * boils down to sending what we have and listening for an ACK
	 * every once in a while.
	 */
	i = 0;
	while ((error = git_revwalk_next(&oid, walk)) == 0) {
		git_pkt_buffer_have(&oid, &data);
		i++;
		if (i % 20 == 0) {
			int pkt_type;

			git_pkt_buffer_flush(&data);
			if (git_buf_oom(&data))
				goto on_error;

			if (gitno_send(transport, data.ptr, data.size, 0) < 0)
				goto on_error;

			pkt_type = recv_pkt(buf);

			if (pkt_type == GIT_PKT_ACK) {
				break;
			} else if (pkt_type == GIT_PKT_NAK) {
				continue;
			} else {
				giterr_set(GITERR_NET, "Unexpected pkt type");
				goto on_error;
			}

		}
	}
	if (error < 0 && error != GIT_REVWALKOVER)
		goto on_error;

	/* Tell the other end that we're done negotiating */
	git_buf_clear(&data);
	git_pkt_buffer_flush(&data);
	git_pkt_buffer_done(&data);
	if (gitno_send(transport, data.ptr, data.size, 0) < 0)
		goto on_error;

	git_buf_free(&data);
	git_revwalk_free(walk);
	return 0;

on_error:
	git_buf_free(&data);
	git_revwalk_free(walk);
	return -1;
}

static int ssh_download_pack(git_transport *transport, git_repository *repo, git_off_t *bytes, git_indexer_stats *stats)
{
	transport_ssh *t = (transport_ssh *) transport;
	int error = 0, read_bytes;
	gitno_buffer *buf = &t->buf;
	git_pkt *pkt;
	const char *line_end, *ptr;

#ifdef SSH_GIT_TRACE
	printf("ssh_download_pack\n");
#endif
	/*
	 * For now, we ignore everything and wait for the pack
	 */
	do {
		ptr = buf->data;
		/* Whilst we're searching for the pack */
		while (1) {
#ifdef SSH_GIT_TRACE
			printf("ssh_download_pack: loop\n");
#endif
			if (buf->offset == 0) {
#ifdef SSH_GIT_TRACE
				printf("ssh_download_pack offset==0\n");
#endif
				break;
			}

			error = git_pkt_parse_line(&pkt, ptr, &line_end, buf->offset);
			if (error == GIT_EBUFS)
				break;

			if (error < 0)
				return error;

			if (pkt->type == GIT_PKT_PACK) {
				git__free(pkt);
				return git_fetch__download_pack(buf->data, buf->offset, transport, repo, bytes, stats);
			}

			/* For now we don't care about anything */
			git__free(pkt);
			gitno_consume(buf, line_end);
		}

		read_bytes = gitno_recv(buf);
	} while (read_bytes);
#ifdef SSH_GIT_TRACE
	printf("read_bytes = %d", read_bytes);
#endif

	return read_bytes;
}

static int ssh_close(git_transport *t)
{
	git_buf buf = GIT_BUF_INIT;

	if (git_pkt_buffer_flush(&buf) < 0)
		return -1;
	/* Can't do anything if there's an error, so don't bother checking  */
	gitno_send(t, buf.ptr, buf.size, 0);

	if (gitno_ssh_teardown(t) < 0) {
		giterr_set(GITERR_NET, "Failed to teardown ssh");
		return -1;
	}

	if (gitno_close(t->socket) < 0) {
		giterr_set(GITERR_NET, "Failed to close socket");
		return -1;
	}

	t->connected = 0;

#ifdef GIT_WIN32
	WSACleanup();
#endif

	return 0;
}

static void ssh_free(git_transport *transport)
{
	transport_ssh *t = (transport_ssh *) transport;
	git_vector *refs = &t->refs;
	unsigned int i;

	for (i = 0; i < refs->length; ++i) {
		git_pkt *p = git_vector_get(refs, i);
		git_pkt_free(p);
	}

	git_vector_free(refs);
	git__free(t->heads);
	git_buf_free(&t->proto.buf);
	git__free(t->parent.url);
	git__free(t);
}

int git_transport_ssh(git_transport **out)
{
	transport_ssh *t;
#ifdef GIT_WIN32
	int ret;
#endif

#ifdef SSH_GIT_TRACE
    printf("tsshUsername=%s\n",sshUsername);
    printf("tsshPassword=%s\n",sshPassword);

#endif

	t = git__malloc(sizeof(transport_ssh));
	GITERR_CHECK_ALLOC(t);

	memset(t, 0x0, sizeof(transport_ssh));


#ifdef SSH_GIT_TRACE
    printf("t2sshUsername=%s\n",sshUsername);
    printf("t2sshPassword=%s\n",sshPassword);

#endif
	t->parent.connect = ssh_connect;
	t->parent.ls = ssh_ls;
	t->parent.negotiate_fetch = ssh_negotiate_fetch;
	t->parent.download_pack = ssh_download_pack;
	t->parent.close = ssh_close;
	t->parent.free = ssh_free;
	t->parent.gitssh = 1;

	t->proto.refs = &t->refs;
	t->proto.transport = (git_transport *) t;

	*out = (git_transport *) t;

#ifdef GIT_WIN32
	ret = WSAStartup(MAKEWORD(2,2), &t->wsd);
	if (ret != 0) {
		git_free(*out);
		giterr_set(GITERR_NET, "Winsock init failed");
		return -1;
	}
#endif

	return 0;
}

