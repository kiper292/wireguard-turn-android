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
extern int wgTurnProxyStart(const char *peer_addr, const char *vklink, const char *mode, int n, int udp, const char *listen_addr, const char *turn_ip, int turn_port, const char *peer_type, int streams_per_cred, int watchdog_timeout, const char *wrap_key, long long network_handle);
extern void wgTurnProxyStop();
extern void wgNotifyNetworkChange();
extern const char* getNetworkDnsServers(long long network_handle);

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
static jclass link_properties_class_global;
static jclass inet_address_class_global;
static jobject connectivity_manager_instance_global;
static jobject current_network_global = NULL;
static jlong current_network_handle = 0;
static jmethodID get_link_properties_method;
static jmethodID get_dns_servers_method;
static jmethodID inet_address_get_host_method;

// Captcha handler
static jclass turn_backend_class_global = NULL;
static jmethodID on_captcha_required_method = NULL;


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
		if (link_properties_class_global) (*env)->DeleteGlobalRef(env, link_properties_class_global);
		if (inet_address_class_global) (*env)->DeleteGlobalRef(env, inet_address_class_global);
		connectivity_manager_class_global = NULL;
		network_class_global = NULL;
		file_descriptor_class_global = NULL;
		connectivity_manager_instance_global = NULL;
		current_network_global = NULL;
		link_properties_class_global = NULL;
		inet_address_class_global = NULL;
		get_link_properties_method = NULL;
		get_dns_servers_method = NULL;
		inet_address_get_host_method = NULL;
		// NOTE: Do NOT reset turn_backend_class_global / on_captcha_required_method here.
		// TurnBackend is a Java class independent of VpnService lifecycle.
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

		// Cache LinkProperties and getDnsServers
		jclass lp_class = (*env)->FindClass(env, "android/net/LinkProperties");
		if (lp_class) {
			link_properties_class_global = (*env)->NewGlobalRef(env, lp_class);
			get_dns_servers_method = (*env)->GetMethodID(env, link_properties_class_global, "getDnsServers", "()Ljava/util/List;");
			(*env)->DeleteLocalRef(env, lp_class);
		}
		get_link_properties_method = (*env)->GetMethodID(env, connectivity_manager_class_global, "getLinkProperties", "(Landroid/net/Network;)Landroid/net/LinkProperties;");

		// Cache InetAddress.getHostAddress()
		jclass ia_class = (*env)->FindClass(env, "java/net/InetAddress");
		if (ia_class) {
			inet_address_class_global = (*env)->NewGlobalRef(env, ia_class);
			inet_address_get_host_method = (*env)->GetMethodID(env, inet_address_class_global, "getHostAddress", "()Ljava/lang/String;");
			(*env)->DeleteLocalRef(env, ia_class);
		}

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
	const char *ifname_jni = (*env)->GetStringUTFChars(env, ifname, 0);
	const char *settings_jni = (*env)->GetStringUTFChars(env, settings, 0);

	// Duplicate strings to avoid MTE issues with JNI-tagged pointers during Go execution
	char *ifname_str = ifname_jni ? strdup(ifname_jni) : NULL;
	char *settings_str = settings_jni ? strdup(settings_jni) : NULL;

	int ret = wgTurnOn((struct go_string){
		.str = ifname_str,
		.n = ifname_str ? (long)strlen(ifname_str) : 0
	}, tun_fd, (struct go_string){
		.str = settings_str,
		.n = settings_str ? (long)strlen(settings_str) : 0
	});

	(*env)->ReleaseStringUTFChars(env, ifname, ifname_jni);
	(*env)->ReleaseStringUTFChars(env, settings, settings_jni);

	free(ifname_str);
	free(settings_str);

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

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_TurnBackend_wgTurnProxyStart(JNIEnv *env, jclass c, jstring peer_addr, jstring vklink, jstring mode, jint n, jint useUdp, jstring listen_addr, jstring turn_ip, jint turn_port, jstring peer_type, jint streams_per_cred, jint watchdog_timeout, jstring wrap_key, jlong network_handle)
{
	const char *peer_addr_jni = (*env)->GetStringUTFChars(env, peer_addr, 0);
	const char *vklink_jni = (*env)->GetStringUTFChars(env, vklink, 0);
	const char *mode_jni = (*env)->GetStringUTFChars(env, mode, 0);
	const char *listen_addr_jni = (*env)->GetStringUTFChars(env, listen_addr, 0);
	const char *turn_ip_jni = (*env)->GetStringUTFChars(env, turn_ip, 0);
	const char *peer_type_jni = (*env)->GetStringUTFChars(env, peer_type, 0);
	const char *wrap_key_jni = (*env)->GetStringUTFChars(env, wrap_key, 0);

	// Duplicate strings to avoid MTE issues with JNI-tagged pointers during Go execution
	char *peer_addr_str = peer_addr_jni ? strdup(peer_addr_jni) : NULL;
	char *vklink_str = vklink_jni ? strdup(vklink_jni) : NULL;
	char *mode_str = mode_jni ? strdup(mode_jni) : NULL;
	char *listen_addr_str = listen_addr_jni ? strdup(listen_addr_jni) : NULL;
	char *turn_ip_str = turn_ip_jni ? strdup(turn_ip_jni) : NULL;
	char *peer_type_str = peer_type_jni ? strdup(peer_type_jni) : NULL;
	char *wrap_key_str = wrap_key_jni ? strdup(wrap_key_jni) : NULL;

	update_current_network(env, network_handle);

	int ret = wgTurnProxyStart(peer_addr_str, vklink_str, mode_str, (int)n, (int)useUdp, listen_addr_str, turn_ip_str, (int)turn_port, peer_type_str, (int)streams_per_cred, (int)watchdog_timeout, wrap_key_str, (long long)network_handle);

	(*env)->ReleaseStringUTFChars(env, peer_addr, peer_addr_jni);
	(*env)->ReleaseStringUTFChars(env, vklink, vklink_jni);
	(*env)->ReleaseStringUTFChars(env, mode, mode_jni);
	(*env)->ReleaseStringUTFChars(env, listen_addr, listen_addr_jni);
	(*env)->ReleaseStringUTFChars(env, turn_ip, turn_ip_jni);
	(*env)->ReleaseStringUTFChars(env, peer_type, peer_type_jni);
	(*env)->ReleaseStringUTFChars(env, wrap_key, wrap_key_jni);

	free(peer_addr_str);
	free(vklink_str);
	free(mode_str);
	free(listen_addr_str);
	free(turn_ip_str);
	free(peer_type_str);
	free(wrap_key_str);

	return ret;
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_TurnBackend_wgNotifyNetworkChange(JNIEnv *env, jclass c)
{
	wgNotifyNetworkChange();
}

JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_TurnBackend_wgGetNetworkDnsServers(JNIEnv *env, jclass c, jlong network_handle)
{
	if (!current_network_global || !connectivity_manager_instance_global || !get_link_properties_method || !get_dns_servers_method || !inet_address_get_host_method)
		return NULL;

	// Find the Network object by handle
	jobject target_network = NULL;
	jobjectArray networks = (jobjectArray)(*env)->CallObjectMethod(env, connectivity_manager_instance_global, get_all_networks_method);
	if (networks) {
		jsize len = (*env)->GetArrayLength(env, networks);
		for (jsize i = 0; i < len; i++) {
			jobject network_obj = (*env)->GetObjectArrayElement(env, networks, i);
			if (network_handle == (*env)->CallLongMethod(env, network_obj, get_network_handle_method)) {
				target_network = network_obj;
				break;
			}
			(*env)->DeleteLocalRef(env, network_obj);
		}
		(*env)->DeleteLocalRef(env, networks);
	}
	if (!target_network)
		return NULL;

	// Get LinkProperties
	jobject link_props = (*env)->CallObjectMethod(env, connectivity_manager_instance_global, get_link_properties_method, target_network);
	(*env)->DeleteLocalRef(env, target_network);
	if (!link_props)
		return NULL;

	// Get DNS servers list
	jobject dns_list = (*env)->CallObjectMethod(env, link_props, get_dns_servers_method);
	(*env)->DeleteLocalRef(env, link_props);
	if (!dns_list)
		return NULL;

	// Get List.size() and List.get() methods
	jclass list_class = (*env)->GetObjectClass(env, dns_list);
	jmethodID size_method = (*env)->GetMethodID(env, list_class, "size", "()I");
	jmethodID get_method = (*env)->GetMethodID(env, list_class, "get", "(I)Ljava/lang/Object;");

	jint count = (*env)->CallIntMethod(env, dns_list, size_method);
	if (count <= 0) {
		(*env)->DeleteLocalRef(env, list_class);
		(*env)->DeleteLocalRef(env, dns_list);
		return NULL;
	}

	// Build comma-separated string
	char result[256] = {0};
	int offset = 0;
	for (jint i = 0; i < count && offset < (int)sizeof(result) - 16; i++) {
		jobject inet_addr = (*env)->CallObjectMethod(env, dns_list, get_method, i);
		if (inet_addr) {
			jstring ip_str = (jstring)(*env)->CallObjectMethod(env, inet_addr, inet_address_get_host_method);
			if (ip_str) {
				const char *ip_cstr = (*env)->GetStringUTFChars(env, ip_str, 0);
				if (offset > 0) result[offset++] = ',';
				offset += snprintf(result + offset, sizeof(result) - offset, "%s", ip_cstr);
				(*env)->ReleaseStringUTFChars(env, ip_str, ip_cstr);
				(*env)->DeleteLocalRef(env, ip_str);
			}
			(*env)->DeleteLocalRef(env, inet_addr);
		}
	}

	(*env)->DeleteLocalRef(env, list_class);
	(*env)->DeleteLocalRef(env, dns_list);

	if (offset == 0)
		return NULL;

	return (*env)->NewStringUTF(env, result);
}

// Called from Go to get system DNS servers for a given network handle.
// Returns a malloc'd comma-separated string of DNS IPs, or NULL.
const char* getNetworkDnsServers(long long network_handle)
{
	if (!connectivity_manager_instance_global || !get_link_properties_method || !get_dns_servers_method || !inet_address_get_host_method)
		return NULL;

	JNIEnv *env;
	int attached = 0;
	if ((*java_vm)->GetEnv(java_vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != JNI_OK)
			return NULL;
		attached = 1;
	}

	const char *result = NULL;

	// Find the Network object by handle
	jobject target_network = NULL;
	jobjectArray networks = (jobjectArray)(*env)->CallObjectMethod(env, connectivity_manager_instance_global, get_all_networks_method);
	if (networks) {
		jsize len = (*env)->GetArrayLength(env, networks);
		for (jsize i = 0; i < len; i++) {
			jobject network_obj = (*env)->GetObjectArrayElement(env, networks, i);
			if (network_handle == (*env)->CallLongMethod(env, network_obj, get_network_handle_method)) {
				target_network = network_obj;
				break;
			}
			(*env)->DeleteLocalRef(env, network_obj);
		}
		(*env)->DeleteLocalRef(env, networks);
	}
	if (!target_network) goto cleanup;

	// Get LinkProperties
	jobject link_props = (*env)->CallObjectMethod(env, connectivity_manager_instance_global, get_link_properties_method, target_network);
	(*env)->DeleteLocalRef(env, target_network);
	if (!link_props) goto cleanup;

	// Get DNS servers list
	jobject dns_list = (jobject)(*env)->CallObjectMethod(env, link_props, get_dns_servers_method);
	(*env)->DeleteLocalRef(env, link_props);
	if (!dns_list) goto cleanup;

	// Get List.size() and List.get() methods
	jclass list_class = (*env)->GetObjectClass(env, dns_list);
	jmethodID size_method = (*env)->GetMethodID(env, list_class, "size", "()I");
	jmethodID get_method = (*env)->GetMethodID(env, list_class, "get", "(I)Ljava/lang/Object;");

	jint count = (*env)->CallIntMethod(env, dns_list, size_method);
	if (count <= 0) {
		(*env)->DeleteLocalRef(env, list_class);
		(*env)->DeleteLocalRef(env, dns_list);
		goto cleanup;
	}

	// Build comma-separated string
	char buf[256] = {0};
	int offset = 0;
	for (jint i = 0; i < count && offset < (int)sizeof(buf) - 16; i++) {
		jobject inet_addr = (*env)->CallObjectMethod(env, dns_list, get_method, i);
		if (inet_addr) {
			jstring ip_str = (jstring)(*env)->CallObjectMethod(env, inet_addr, inet_address_get_host_method);
			if (ip_str) {
				const char *ip_cstr = (*env)->GetStringUTFChars(env, ip_str, 0);
				if (offset > 0) buf[offset++] = ',';
				offset += snprintf(buf + offset, sizeof(buf) - offset, "%s", ip_cstr);
				(*env)->ReleaseStringUTFChars(env, ip_str, ip_cstr);
				(*env)->DeleteLocalRef(env, ip_str);
			}
			(*env)->DeleteLocalRef(env, inet_addr);
		}
	}

	(*env)->DeleteLocalRef(env, list_class);
	(*env)->DeleteLocalRef(env, dns_list);

	if (offset > 0) {
		result = strdup(buf);
	}

cleanup:
	if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
	if (attached) (*java_vm)->DetachCurrentThread(java_vm);
	return result;
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
