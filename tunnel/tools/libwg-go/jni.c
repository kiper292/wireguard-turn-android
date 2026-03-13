/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2017-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct go_string { const char *str; long n; };
extern int wgTurnOn(struct go_string ifname, int tun_fd, struct go_string settings);
extern void wgTurnOff(int handle);
extern int wgGetSocketV4(int handle);
extern int wgGetSocketV6(int handle);
extern char *wgGetConfig(int handle);
extern char *wgVersion();
extern int wgTurnProxyStart(struct go_string peer_addr, struct go_string vklink, int n, int udp, struct go_string listen_addr);
extern void wgTurnProxyStop();

static JavaVM *java_vm;
static jobject vpn_service_global;
static jmethodID protect_method;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
	java_vm = vm;
	return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_GoBackend_wgSetVpnService(JNIEnv *env, jclass c, jobject vpn_service)
{
	if (vpn_service_global) {
		(*env)->DeleteGlobalRef(env, vpn_service_global);
		vpn_service_global = NULL;
		protect_method = NULL;
	}
	if (vpn_service) {
		vpn_service_global = (*env)->NewGlobalRef(env, vpn_service);
		jclass vpn_service_class = (*env)->GetObjectClass(env, vpn_service_global);
		protect_method = (*env)->GetMethodID(env, vpn_service_class, "protect", "(I)Z");
	}
}

int wgProtectSocket(int fd)
{
	JNIEnv *env;
	int ret = 0;
	int attached = 0;
	if (!vpn_service_global || !protect_method)
		return -1;
	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0)
			return -1;
		attached = 1;
	}
	if ((*env)->CallBooleanMethod(env, vpn_service_global, protect_method, (jint)fd))
		ret = 0;
	else
		ret = -1;
	if (attached)
		(*java_vm)->DetachCurrentThread(java_vm);
	return ret;
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOn(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings)
{
	const char *ifname_str = (*env)->GetStringUTFChars(env, ifname, 0);
	size_t ifname_len = (*env)->GetStringUTFLength(env, ifname);
	const char *settings_str = (*env)->GetStringUTFChars(env, settings, 0);
	size_t settings_len = (*env)->GetStringUTFLength(env, settings);
	int ret = wgTurnOn((struct go_string){
		.str = ifname_str,
		.n = ifname_len
	}, tun_fd, (struct go_string){
		.str = settings_str,
		.n = settings_len
	});
	(*env)->ReleaseStringUTFChars(env, ifname, ifname_str);
	(*env)->ReleaseStringUTFChars(env, settings, settings_str);
	return ret;
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOff(JNIEnv *env, jclass c, jint handle)
{
	wgTurnOff(handle);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetSocketV4(JNIEnv *env, jclass c, jint handle)
{
	return wgGetSocketV4(handle);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetSocketV6(JNIEnv *env, jclass c, jint handle)
{
	return wgGetSocketV6(handle);
}

JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetConfig(JNIEnv *env, jclass c, jint handle)
{
	jstring ret;
	char *config = wgGetConfig(handle);
	if (!config)
		return NULL;
	ret = (*env)->NewStringUTF(env, config);
	free(config);
	return ret;
}

JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_GoBackend_wgVersion(JNIEnv *env, jclass c)
{
	jstring ret;
	char *version = wgVersion();
	if (!version)
		return NULL;
	ret = (*env)->NewStringUTF(env, version);
	free(version);
	return ret;
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnProxyStart(JNIEnv *env, jclass c, jstring peer_addr, jstring vklink, jint n, jboolean udp, jstring listen_addr)
{
	const char *peer_addr_str = (*env)->GetStringUTFChars(env, peer_addr, 0);
	size_t peer_addr_len = (*env)->GetStringUTFLength(env, peer_addr);
	const char *vklink_str = (*env)->GetStringUTFChars(env, vklink, 0);
	size_t vklink_len = (*env)->GetStringUTFLength(env, vklink);
	const char *listen_addr_str = (*env)->GetStringUTFChars(env, listen_addr, 0);
	size_t listen_addr_len = (*env)->GetStringUTFLength(env, listen_addr);
	int ret = wgTurnProxyStart((struct go_string){
		.str = peer_addr_str,
		.n = peer_addr_len
	}, (struct go_string){
		.str = vklink_str,
		.n = vklink_len
	}, n, udp, (struct go_string){
		.str = listen_addr_str,
		.n = listen_addr_len
	});
	(*env)->ReleaseStringUTFChars(env, peer_addr, peer_addr_str);
	(*env)->ReleaseStringUTFChars(env, vklink, vklink_str);
	(*env)->ReleaseStringUTFChars(env, listen_addr, listen_addr_str);
	return ret;
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnProxyStop(JNIEnv *env, jclass c)
{
	wgTurnProxyStop();
}
