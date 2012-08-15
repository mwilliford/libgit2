/*
 * Copyright (C) 2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_ssh_h__
#define INCLUDE_git_ssh_h__

#include "common.h"
#include "types.h"



/**
 * @file git2/ssh.h
 * @brief Git ssh setup calls
 * @defgroup git_ssh Git ssh setup calls
 * @ingroup Git
 * @{
 */
GIT_BEGIN_DECL

typedef enum git_ssh_auth_type {
	GIT_SSH_AUTH_PASSWORD,
	GIT_SSH_AUTH_KEY
} git_ssh_auth_type;



/**
 * Setup authentication type for ssh authentication
 *
 * @param enum git_ssh_auth_type
 *
 */
GIT_EXTERN(int) git_ssh_auth_setup(git_ssh_auth_type  auth_type);

/**
 * Set username and password for password authentication
 *
 * @param username
 * @param password
 *
 */
GIT_EXTERN(int) git_ssh_password_auth(const char* username,const char* password);

/**
*
* Set the public and private keyfile paths, as well as any keystore keypass
*
* @param public keyfile
* @param private keyfile
* @param keystore password
*
*/
GIT_EXTERN(int) git_ssh_keyfileinfo(const char* publickey,
                                         const char* privatekey,
                                         const char* keypass);

/** @} */
GIT_END_DECL
#endif
