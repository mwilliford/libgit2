#include "clar_libgit2.h"
#include "git2/clone.h"
#include "git2/ssh.h"

#include "repository.h"

#define DO_LOCAL_TEST 0
#define SSH_LIVE_NETWORK_TESTS 1
#define SSH_LIVE_REPO "git@github.com:mwilliford/testgit.git"

static git_repository *g_repo;


void test_ssh_ssh__initialize(void)
{
	g_repo = NULL;

}

void test_ssh_ssh__cleanup(void)
{
	if (g_repo) {
		git_repository_free(g_repo);
		g_repo = NULL;
	}

}

#ifdef SSH_LIVE_NETWORK_TESTS
void test_ssh_ssh__net_test(void)
{
		git_ssh_auth_type at = GIT_SSH_AUTH_PASSWORD;
		git_ssh_auth_setup(at);

		git_ssh_password_auth("mwilliford","");
		//git_ssh_keyfileinfo("/Users/marcus/.ssh/id_rsa.pub",
		 //                                        "/Users/marcus/.ssh/id_rsa",
		  //                                       "");

		git_remote *origin;
		git_futils_rmdir_r("./test", GIT_DIRREMOVAL_FILES_AND_DIRS);

		cl_git_pass(git_clone_bare(&g_repo, SSH_LIVE_REPO, "test", NULL));
		cl_assert(git_repository_is_bare(g_repo));
		cl_git_pass(git_remote_load(&origin, g_repo, "origin"));
		git_futils_rmdir_r("./test", GIT_DIRREMOVAL_FILES_AND_DIRS);
}





#endif
