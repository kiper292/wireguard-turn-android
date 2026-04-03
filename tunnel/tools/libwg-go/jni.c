/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2017-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <jni.h>
#include <android/log.h>
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
extern int wgTurnProxyStart(const char *peer_addr, const char *vklink, int n, int udp, const char *listen_addr, const char *turn_ip, int turn_port, int no_dtls, long long network_handle);
extern void wgTurnProxyStop();
extern void wgNotifyNetworkChange();

static jclass turn_backend_class_global = NULL;
static jmethodID on_captcha_required_method = NULL;

static JavaVM *java_vm;
static jobject vpn_service_global;
static jmethodID protect_method;
static jmethodID get_system_service_method;
static jmethodID get_all_networks_method;
static jmethodID get_network_handle_method;
static jmethodID bind_socket_method;
static jfieldID file_descriptor_descriptor;
static jmethodID file_descriptor_init;
static jclass connectivity_manager_class_global;
static jclass network_class_global;
static jclass file_descriptor_class_global;
static jobject connectivity_manager_instance_global;
static jobject current_network_global = NULL;
static jlong current_network_handle = 0;


// Helper to update the cached Network object
static void update_current_network(JNIEnv *env, jlong handle)
{
	if (current_network_global) {
		(*env)->DeleteGlobalRef(env, current_network_global);
		current_network_global = NULL;
	}
	current_network_handle = handle;

	if (handle == 0 || !connectivity_manager_instance_global || !get_all_networks_method || !get_network_handle_method)
		return;

	jobjectArray networks = (jobjectArray)(*env)->CallObjectMethod(env, connectivity_manager_instance_global, get_all_networks_method);
	if (networks) {
		jsize len = (*env)->GetArrayLength(env, networks);
		for (jsize i = 0; i < len; i++) {
			jobject network_obj = (*env)->GetObjectArrayElement(env, networks, i);
			if (handle == (*env)->CallLongMethod(env, network_obj, get_network_handle_method)) {
				current_network_global = (*env)->NewGlobalRef(env, network_obj);
				(*env)->DeleteLocalRef(env, network_obj);
				break;
			}
			(*env)->DeleteLocalRef(env, network_obj);
		}
		(*env)->DeleteLocalRef(env, networks);
	}
	if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
	
	if (!current_network_global) {
		__android_log_print(ANDROID_LOG_WARN, "WireGuard/JNI", "update_current_network: FAILED - network not found for handle=%lld", (long long)handle);
	}
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
	java_vm = vm;
	return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_TurnBackend_wgSetVpnService(JNIEnv *env, jclass c, jobject vpn_service)
{
	if (vpn_service_global) {
		(*env)->DeleteGlobalRef(env, vpn_service_global);
		vpn_service_global = NULL;
		protect_method = NULL;
		get_system_service_method = NULL;
		get_all_networks_method = NULL;
		get_network_handle_method = NULL;
		bind_socket_method = NULL;
		file_descriptor_descriptor = NULL;
		file_descriptor_init = NULL;
		if (connectivity_manager_class_global) (*env)->DeleteGlobalRef(env, connectivity_manager_class_global);
		if (network_class_global) (*env)->DeleteGlobalRef(env, network_class_global);
		if (file_descriptor_class_global) (*env)->DeleteGlobalRef(env, file_descriptor_class_global);
		if (connectivity_manager_instance_global) (*env)->DeleteGlobalRef(env, connectivity_manager_instance_global);
		if (current_network_global) (*env)->DeleteGlobalRef(env, current_network_global);
		connectivity_manager_class_global = NULL;
		network_class_global = NULL;
		file_descriptor_class_global = NULL;
		connectivity_manager_instance_global = NULL;
		current_network_global = NULL;
	}
	if (vpn_service) {
		vpn_service_global = (*env)->NewGlobalRef(env, vpn_service);
		jclass vpn_service_class = (*env)->GetObjectClass(env, vpn_service_global);
		protect_method = (*env)->GetMethodID(env, vpn_service_class, "protect", "(I)Z");
		get_system_service_method = (*env)->GetMethodID(env, vpn_service_class, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");

		// Cache TurnBackend class and captcha method
		if (!turn_backend_class_global) {
			jclass tb_class = (*env)->FindClass(env, "com/wireguard/android/backend/TurnBackend");
			if (tb_class) {
				turn_backend_class_global = (*env)->NewGlobalRef(env, tb_class);
				on_captcha_required_method = (*env)->GetStaticMethodID(env, turn_backend_class_global, "onCaptchaRequired", "(Ljava/lang/String;)Ljava/lang/String;");
				(*env)->DeleteLocalRef(env, tb_class);
			}
		}
		
		jclass cm_class = (*env)->FindClass(env, "android/net/ConnectivityManager");
		connectivity_manager_class_global = (*env)->NewGlobalRef(env, cm_class);
		get_all_networks_method = (*env)->GetMethodID(env, connectivity_manager_class_global, "getAllNetworks", "()[Landroid/net/Network;");
		
		jclass n_class = (*env)->FindClass(env, "android/net/Network");
		network_class_global = (*env)->NewGlobalRef(env, n_class);
		get_network_handle_method = (*env)->GetMethodID(env, network_class_global, "getNetworkHandle", "()J");
		bind_socket_method = (*env)->GetMethodID(env, network_class_global, "bindSocket", "(Ljava/io/FileDescriptor;)V");
		
		jclass fd_class = (*env)->FindClass(env, "java/io/FileDescriptor");
		file_descriptor_class_global = (*env)->NewGlobalRef(env, fd_class);
		file_descriptor_init = (*env)->GetMethodID(env, file_descriptor_class_global, "<init>", "()V");
		file_descriptor_descriptor = (*env)->GetFieldID(env, file_descriptor_class_global, "descriptor", "I");

		jstring cm_service_name = (*env)->NewStringUTF(env, "connectivity");
		jobject cm_obj = (*env)->CallObjectMethod(env, vpn_service_global, get_system_service_method, cm_service_name);
		if (cm_obj) {
			connectivity_manager_instance_global = (*env)->NewGlobalRef(env, cm_obj);
			(*env)->DeleteLocalRef(env, cm_obj);
		}
		(*env)->DeleteLocalRef(env, cm_service_name);
	}
}

int wgProtectSocket(int fd)
{
	JNIEnv *env;
	int ret = 0;
	int attached = 0;

	// Validate fd
	if (fd < 0) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"wgProtectSocket: invalid fd=%d", fd);
		return -1;
	}

	if (!vpn_service_global || !protect_method) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"wgProtectSocket(fd=%d): vpn_service_global is NULL! CANNOT PROTECT", fd);
		return -1;
	}
	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0) {
			__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
				"wgProtectSocket(fd=%d): AttachCurrentThread failed", fd);
			return -1;
		}
		attached = 1;
	}

	if ((*env)->CallBooleanMethod(env, vpn_service_global, protect_method, (jint)fd)) {
        // Use cached network object for immediate binding
        if (current_network_global && bind_socket_method) {
            jobject fd_obj = (*env)->NewObject(env, file_descriptor_class_global, file_descriptor_init);
			(*env)->SetIntField(env, fd_obj, file_descriptor_descriptor, fd);
			(*env)->CallVoidMethod(env, current_network_global, bind_socket_method, fd_obj);
			if ((*env)->ExceptionCheck(env)) {
				__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI", "wgProtectSocket(fd=%d): bindSocket exception!", fd);
				(*env)->ExceptionClear(env);
			} else {
				__android_log_print(ANDROID_LOG_INFO, "WireGuard/JNI", "wgProtectSocket(fd=%d): SUCCESS (protected + bound to net %lld)", fd, (long long)current_network_handle);
			}
			(*env)->DeleteLocalRef(env, fd_obj);
		} else {
            __android_log_print(ANDROID_LOG_INFO, "WireGuard/JNI", "wgProtectSocket(fd=%d): SUCCESS (protected, but NOT bound - handle=%lld)", fd, (long long)current_network_handle);
        }
		ret = 0;
	} else {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"wgProtectSocket(fd=%d): VpnService.protect() FAILED", fd);
		ret = -1;
	}
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

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_TurnBackend_wgTurnProxyStart(JNIEnv *env, jclass c, jstring peer_addr, jstring vklink, jint n, jint useUdp, jstring listen_addr, jstring turn_ip, jint turn_port, jint no_dtls, jlong network_handle)
{
	const char *peer_addr_str = (*env)->GetStringUTFChars(env, peer_addr, 0);
	const char *vklink_str = (*env)->GetStringUTFChars(env, vklink, 0);
	const char *listen_addr_str = (*env)->GetStringUTFChars(env, listen_addr, 0);
	const char *turn_ip_str = (*env)->GetStringUTFChars(env, turn_ip, 0);
	
	update_current_network(env, network_handle);
	
	int ret = wgTurnProxyStart(peer_addr_str, vklink_str, (int)n, (int)useUdp, listen_addr_str, turn_ip_str, (int)turn_port, (int)no_dtls, (long long)network_handle);
	(*env)->ReleaseStringUTFChars(env, peer_addr, peer_addr_str);
	(*env)->ReleaseStringUTFChars(env, vklink, vklink_str);
	(*env)->ReleaseStringUTFChars(env, listen_addr, listen_addr_str);
	(*env)->ReleaseStringUTFChars(env, turn_ip, turn_ip_str);
	return ret;
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_TurnBackend_wgNotifyNetworkChange(JNIEnv *env, jclass c)
{
	wgNotifyNetworkChange();
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_TurnBackend_wgTurnProxyStop(JNIEnv *env, jclass c)
{
	update_current_network(env, 0);
	wgTurnProxyStop();
}

// Called from Go to request captcha solving from Android UI.
// Blocks until the user solves the captcha or timeout.
// Returns a malloc'd string that the caller (Go) must free.
const char* requestCaptcha(const char* redirect_uri)
{
	JNIEnv *env;
	int attached = 0;
	const char* result = NULL;

	if (!java_vm || !turn_backend_class_global || !on_captcha_required_method) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"requestCaptcha: JNI not initialized (vm=%p, class=%p, method=%p)",
			java_vm, turn_backend_class_global, on_captcha_required_method);
		return NULL;
	}

	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0) {
			__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
				"requestCaptcha: AttachCurrentThread failed");
			return NULL;
		}
		attached = 1;
	}

	jstring j_uri = (*env)->NewStringUTF(env, redirect_uri);
	jstring j_result = (jstring)(*env)->CallStaticObjectMethod(env, turn_backend_class_global,
		on_captcha_required_method, j_uri);
	(*env)->DeleteLocalRef(env, j_uri);

	if ((*env)->ExceptionCheck(env)) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"requestCaptcha: exception occurred");
		(*env)->ExceptionClear(env);
	} else if (j_result != NULL) {
		const char* str = (*env)->GetStringUTFChars(env, j_result, NULL);
		if (str && strlen(str) > 0) {
			result = strdup(str);
		}
		(*env)->ReleaseStringUTFChars(env, j_result, str);
		(*env)->DeleteLocalRef(env, j_result);
	}

	if (attached)
		(*java_vm)->DetachCurrentThread(java_vm);

	__android_log_print(ANDROID_LOG_INFO, "WireGuard/JNI",
		"requestCaptcha: returning %s", result ? "token" : "NULL");
	return result;
}
