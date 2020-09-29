# kube-apiserver源码分析

kube-apiserver 编译完成 启动参数如下

```
[root@MiWiFi-RM2100-srv ~]# ps -ef|grep api
root     2255090 2254696 35 20:34 pts/0    00:00:05 /root/go/src/k8s.io/Kubernetes/_output/bin/kube-apiserver --authorization-mode=Node,RBAC  --cloud-provider= --cloud-config=   --v=3 --vmodule= --audit-policy-file=/tmp/kube-audit-policy-file --audit-log-path=/tmp/kube-apiserver-audit.log --authorization-webhook-config-file= --authentication-token-webhook-config-file= --cert-dir=/var/run/kubernetes --client-ca-file=/var/run/kubernetes/client-ca.crt --kubelet-client-certificate=/var/run/kubernetes/client-kube-apiserver.crt --kubelet-client-key=/var/run/kubernetes/client-kube-apiserver.key --service-account-key-file=/tmp/kube-serviceaccount.key --service-account-lookup=true --service-account-issuer=https://kubernetes.default.svc --service-account-signing-key-file=/tmp/kube-serviceaccount.key --enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,Priority,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota --disable-admission-plugins= --admission-control-config-file= --bind-address=0.0.0.0 --secure-port=6443 --tls-cert-file=/var/run/kubernetes/serving-kube-apiserver.crt --tls-private-key-file=/var/run/kubernetes/serving-kube-apiserver.key --insecure-bind-address=127.0.0.1 --insecure-port=8080 --storage-backend=etcd3 --storage-media-type=application/vnd.kubernetes.protobuf --etcd-servers=http://127.0.0.1:2379 --service-cluster-ip-range=10.0.0.0/24 --feature-gates=AllAlpha=false --external-hostname=localhost --requestheader-username-headers=X-Remote-User --requestheader-group-headers=X-Remote-Group --requestheader-extra-headers-prefix=X-Remote-Extra- --requestheader-client-ca-file=/var/run/kubernetes/request-header-ca.crt --requestheader-allowed-names=system:auth-proxy --proxy-client-cert-file=/var/run/kubernetes/client-auth-proxy.crt --proxy-client-key-file=/var/run/kubernetes/client-auth-proxy.key --cors-allowed-origins=/127.0.0.1(:[0-9]+)?$,/localhost(:[0-9]+)?$
```

首先要明确这些参数是如何通过cobra传递的

kubernetes修改了cobra库，并没有用到init

```
func OnInitialize(y ...func()) {
	initializers = append(initializers, y...)
}
这个函数并没有被调用
可以查看
https://github.com/spf13/cobra
init的用法
```

编译完成，进程启动在k8s.io\Kubernetes\cmd\kube-apiserver\app\server.go中

```
s := options.NewServerRunOptions()
初始化操作配置，相当于调用了init函数
```



```
const (
	etcdRetryLimit    = 60
	etcdRetryInterval = 1 * time.Second
)

// NewAPIServerCommand creates a *cobra.Command object with default parameters
func NewAPIServerCommand() *cobra.Command {
	s := options.NewServerRunOptions()
	cmd := &cobra.Command{
		Use: "kube-apiserver",
		Long: `The Kubernetes API server validates and configures data
for the api objects which include pods, services, replicationcontrollers, and
others. The API Server services REST operations and provides the frontend to the
cluster's shared state through which all other components interact.`,

		// stop printing usage when the command errors
		SilenceUsage: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
```

```
打印出s的值
( * options.ServerRunOptions) {
	GenericServerRunOptions: ( * options.ServerRunOptions) {
		AdvertiseAddress: net.IP(nil),
		CorsAllowedOriginList: [] string(nil),
		ExternalHost: "",
		MaxRequestsInFlight: 400,
		MaxMutatingRequestsInFlight: 200,
		RequestTimeout: time.Duration(60000000000),
		GoawayChance: 0,
		LivezGracePeriod: time.Duration(0),
		MinRequestTimeout: 1800,
		ShutdownDelayDuration: time.Duration(0),
		JSONPatchMaxCopyBytes: 3145728,
		MaxRequestBodyBytes: 3145728,
		EnablePriorityAndFairness: true
	},
	Etcd: ( * options.EtcdOptions) {
		StorageConfig: storagebackend.Config {
			Type: "",
			Prefix: "/registry",
			Transport: storagebackend.TransportConfig {
				ServerList: [] string(nil),
				KeyFile: "",
				CertFile: "",
				TrustedCAFile: "",
				EgressLookup: (egressselector.Lookup)(0x0000000000000000)
			},
			Paging: true,
			Codec: runtime.Codec(nil),
			EncodeVersioner: runtime.GroupVersioner(nil),
			Transformer: value.Transformer(nil),
			CompactionInterval: time.Duration(300000000000),
			CountMetricPollPeriod: time.Duration(60000000000),
			DBMetricPollInterval: time.Duration(30000000000)
		},
		EncryptionProviderConfigFilepath: "",
		EtcdServersOverrides: [] string(nil),
		DefaultStorageMediaType: "application/vnd.kubernetes.protobuf",
		DeleteCollectionWorkers: 1,
		EnableGarbageCollection: true,
		EnableWatchCache: true,
		DefaultWatchCacheSize: 100,
		WatchCacheSizes: [] string(nil)
	},
	SecureServing: ( * options.SecureServingOptionsWithLoopback) {
		SecureServingOptions: ( * options.SecureServingOptions) {
			BindAddress: net.IP {
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				255,
				255,
				0,
				0,
				0,
				0
			},
			BindPort: 6443,
			BindNetwork: "",
			Required: true,
			ExternalAddress: net.IP(nil),
			Listener: net.Listener(nil),
			ServerCert: options.GeneratableKeyCert {
				CertKey: options.CertKey {
					CertFile: "",
					KeyFile: ""
				},
				CertDirectory: "/var/run/kubernetes",
				PairName: "apiserver",
				GeneratedCert: dynamiccertificates.CertKeyContentProvider(nil),
				FixtureDirectory: ""
			},
			SNICertKeys: [] flag.NamedCertKey(nil),
			CipherSuites: [] string(nil),
			MinTLSVersion: "",
			HTTP2MaxStreamsPerConnection: 0,
			PermitPortSharing: false
		}
	},
	InsecureServing: ( * options.DeprecatedInsecureServingOptionsWithLoopback) {
		DeprecatedInsecureServingOptions: ( * options.DeprecatedInsecureServingOptions) {
			BindAddress: net.IP {
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				255,
				255,
				127,
				0,
				0,
				1
			},
			BindPort: 8080,
			BindNetwork: "",
			Listener: net.Listener(nil),
			ListenFunc: (func(string, string, net.ListenConfig)(net.Listener, int, error))(0x0000000000000000)
		}
	},
	Audit: ( * options.AuditOptions) {
		PolicyFile: "",
		LogOptions: options.AuditLogOptions {
			Path: "",
			MaxAge: 0,
			MaxBackups: 0,
			MaxSize: 0,
			Format: "json",
			BatchOptions: options.AuditBatchOptions {
				Mode: "blocking",
				BatchConfig: buffered.BatchConfig {
					BufferSize: 10000,
					MaxBatchSize: 1,
					MaxBatchWait: time.Duration(0),
					ThrottleEnable: false,
					ThrottleQPS: 0,
					ThrottleBurst: 0,
					AsyncDelegate: false
				}
			},
			TruncateOptions: options.AuditTruncateOptions {
				Enabled: false,
				TruncateConfig: truncate.Config {
					MaxEventSize: 102400,
					MaxBatchSize: 10485760
				}
			},
			GroupVersionString: "audit.k8s.io/v1"
		},
		WebhookOptions: options.AuditWebhookOptions {
			ConfigFile: "",
			InitialBackoff: time.Duration(10000000000),
			BatchOptions: options.AuditBatchOptions {
				Mode: "batch",
				BatchConfig: buffered.BatchConfig {
					BufferSize: 10000,
					MaxBatchSize: 400,
					MaxBatchWait: time.Duration(30000000000),
					ThrottleEnable: true,
					ThrottleQPS: 10,
					ThrottleBurst: 15,
					AsyncDelegate: true
				}
			},
			TruncateOptions: options.AuditTruncateOptions {
				Enabled: false,
				TruncateConfig: truncate.Config {
					MaxEventSize: 102400,
					MaxBatchSize: 10485760
				}
			},
			GroupVersionString: "audit.k8s.io/v1"
		}
	},
	Features: ( * options.FeatureOptions) {
		EnableProfiling: true,
		EnableContentionProfiling: false
	},
	Admission: ( * options.AdmissionOptions) {
		GenericAdmission: ( * options.AdmissionOptions) {
			RecommendedPluginOrder: [] string {
				"AlwaysAdmit",
				"NamespaceAutoProvision",
				"NamespaceLifecycle",
				"NamespaceExists",
				"SecurityContextDeny",
				"LimitPodHardAntiAffinityTopology",
				"LimitRanger",
				"ServiceAccount",
				"NodeRestriction",
				"TaintNodesByCondition",
				"AlwaysPullImages",
				"ImagePolicyWebhook",
				"PodSecurityPolicy",
				"PodNodeSelector",
				"Priority",
				"DefaultTolerationSeconds",
				"PodTolerationRestriction",
				"DenyEscalatingExec",
				"DenyExecOnPrivileged",
				"EventRateLimit",
				"ExtendedResourceToleration",
				"PersistentVolumeLabel",
				"DefaultStorageClass",
				"StorageObjectInUseProtection",
				"OwnerReferencesPermissionEnforcement",
				"PersistentVolumeClaimResize",
				"RuntimeClass",
				"CertificateApproval",
				"CertificateSigning",
				"CertificateSubjectRestriction",
				"DefaultIngressClass",
				"MutatingAdmissionWebhook",
				"ValidatingAdmissionWebhook",
				"ResourceQuota",
				"AlwaysDeny"
			},
			DefaultOffPlugins: sets.String {
				"AlwaysAdmit": sets.Empty {},
				"AlwaysDeny": sets.Empty {},
				"AlwaysPullImages": sets.Empty {},
				"DenyEscalatingExec": sets.Empty {},
				"DenyExecOnPrivileged": sets.Empty {},
				"EventRateLimit": sets.Empty {},
				"ExtendedResourceToleration": sets.Empty {},
				"ImagePolicyWebhook": sets.Empty {},
				"LimitPodHardAntiAffinityTopology": sets.Empty {},
				"NamespaceAutoProvision": sets.Empty {},
				"NamespaceExists": sets.Empty {},
				"NodeRestriction": sets.Empty {},
				"OwnerReferencesPermissionEnforcement": sets.Empty {},
				"PersistentVolumeLabel": sets.Empty {},
				"PodNodeSelector": sets.Empty {},
				"PodSecurityPolicy": sets.Empty {},
				"PodTolerationRestriction": sets.Empty {},
				"SecurityContextDeny": sets.Empty {}
			},
			EnablePlugins: [] string(nil),
			DisablePlugins: [] string(nil),
			ConfigFile: "",
			Plugins: ( * admission.Plugins) {
				lock: sync.Mutex {
					state: 0,
					sema: 0
				},
				registry: map[string](admission.Factory) {
					"AlwaysAdmit": (admission.Factory)(0x00000000032dd720),
					"AlwaysDeny": (admission.Factory)(0x00000000032ec9e0),
					"AlwaysPullImages": (admission.Factory)(0x00000000032ddfa0),
					"CertificateApproval": (admission.Factory)(0x00000000032e2b80),
					"CertificateSigning": (admission.Factory)(0x00000000032e38e0),
					"CertificateSubjectRestriction": (admission.Factory)(0x00000000032e4360),
					"DefaultIngressClass": (admission.Factory)(0x00000000032eb7a0),
					"DefaultStorageClass": (admission.Factory)(0x00000000033634a0),
					"DefaultTolerationSeconds": (admission.Factory)(0x00000000032ec440),
					"DenyEscalatingExec": (admission.Factory)(0x00000000032f2580),
					"DenyExecOnPrivileged": (admission.Factory)(0x00000000032f2740),
					"EventRateLimit": (admission.Factory)(0x00000000032f1740),
					"ExtendedResourceToleration": (admission.Factory)(0x00000000032f3500),
					"ImagePolicyWebhook": (admission.Factory)(0x0000000003304380),
					"LimitPodHardAntiAffinityTopology": (admission.Factory)(0x00000000032dec60),
					"LimitRanger": (admission.Factory)(0x000000000330d280),
					"MutatingAdmissionWebhook": (admission.Factory)(0x00000000019ba940),
					"NamespaceAutoProvision": (admission.Factory)(0x000000000330e0c0),
					"NamespaceExists": (admission.Factory)(0x000000000330ed00),
					"NamespaceLifecycle": (admission.Factory)(0x0000000001987ec0),
					"NodeRestriction": (admission.Factory)(0x0000000003320080),
					"OwnerReferencesPermissionEnforcement": (admission.Factory)(0x00000000032f5980),
					"PersistentVolumeClaimResize": (admission.Factory)(0x0000000003361e80),
					"PersistentVolumeLabel": (admission.Factory)(0x0000000003361220),
					"PodNodeSelector": (admission.Factory)(0x0000000003322ba0),
					"PodSecurityPolicy": (admission.Factory)(0x00000000033465e0),
					"PodTolerationRestriction": (admission.Factory)(0x0000000003328d80),
					"Priority": (admission.Factory)(0x000000000332aae0),
					"ResourceQuota": (admission.Factory)(0x0000000003371580),
					"RuntimeClass": (admission.Factory)(0x000000000332ebe0),
					"SecurityContextDeny": (admission.Factory)(0x0000000003347be0),
					"ServiceAccount": (admission.Factory)(0x000000000334c620),
					"StorageObjectInUseProtection": (admission.Factory)(0x0000000003364260),
					"TaintNodesByCondition": (admission.Factory)(0x0000000003320e60),
					"ValidatingAdmissionWebhook": (admission.Factory)(0x00000000019bdfc0)
				}
			},
			Decorators: admission.Decorators {
				(admission.DecoratorFunc)(0x00000000019955e0)
			}
		},
		PluginNames: [] string(nil)
	},
	Authentication: ( * options.BuiltInAuthenticationOptions) {
		APIAudiences: [] string(nil),
		Anonymous: ( * options.AnonymousAuthenticationOptions) {
			Allow: true
		},
		BootstrapToken: ( * options.BootstrapTokenAuthenticationOptions) {
			Enable: false
		},
		ClientCert: ( * options.ClientCertAuthenticationOptions) {
			ClientCA: "",
			CAContentProvider: dynamiccertificates.CAContentProvider(nil)
		},
		OIDC: ( * options.OIDCAuthenticationOptions) {
			CAFile: "",
			ClientID: "",
			IssuerURL: "",
			UsernameClaim: "",
			UsernamePrefix: "",
			GroupsClaim: "",
			GroupsPrefix: "",
			SigningAlgs: [] string(nil),
			RequiredClaims: map[string] string(nil)
		},
		RequestHeader: ( * options.RequestHeaderAuthenticationOptions) {
			ClientCAFile: "",
			UsernameHeaders: [] string(nil),
			GroupHeaders: [] string(nil),
			ExtraHeaderPrefixes: [] string(nil),
			AllowedNames: [] string(nil)
		},
		ServiceAccounts: ( * options.ServiceAccountAuthenticationOptions) {
			KeyFiles: [] string(nil),
			Lookup: true,
			Issuer: "",
			JWKSURI: "",
			MaxExpiration: time.Duration(0),
			ExtendExpiration: false
		},
		TokenFile: ( * options.TokenFileAuthenticationOptions) {
			TokenFile: ""
		},
		WebHook: ( * options.WebHookAuthenticationOptions) {
			ConfigFile: "",
			Version: "v1beta1",
			CacheTTL: time.Duration(120000000000)
		},
		TokenSuccessCacheTTL: time.Duration(10000000000),
		TokenFailureCacheTTL: time.Duration(0)
	},
	Authorization: ( * options.BuiltInAuthorizationOptions) {
		Modes: [] string {
			"AlwaysAllow"
		},
		PolicyFile: "",
		WebhookConfigFile: "",
		WebhookVersion: "v1beta1",
		WebhookCacheAuthorizedTTL: time.Duration(300000000000),
		WebhookCacheUnauthorizedTTL: time.Duration(30000000000)
	},
	CloudProvider: ( * options.CloudProviderOptions) {
		CloudConfigFile: "",
		CloudProvider: ""
	},
	APIEnablement: ( * options.APIEnablementOptions) {
		RuntimeConfig: flag.ConfigurationMap {}
	},
	EgressSelector: ( * options.EgressSelectorOptions) {
		ConfigFile: ""
	},
	Metrics: ( * metrics.Options) {
		ShowHiddenMetricsForVersion: ""
	},
	Logs: ( * logs.Options) {
		LogFormat: "text"
	},
	AllowPrivileged: false,
	EnableLogsHandler: true,
	EventTTL: time.Duration(3600000000000),
	KubeletConfig: client.KubeletClientConfig {
		Port: 10250,
		ReadOnlyPort: 10255,
		PreferredAddressTypes: [] string {
			"Hostname",
			"InternalDNS",
			"InternalIP",
			"ExternalDNS",
			"ExternalIP"
		},
		TLSClientConfig: rest.TLSClientConfig {
			Insecure: false,
			ServerName: "",
			CertFile: "",
			KeyFile: "",
			CAFile: "",
			CertData: [] uint8(nil),
			KeyData: [] uint8(nil),
			CAData: [] uint8(nil),
			NextProtos: [] string(nil)
		},
		BearerToken: "",
		HTTPTimeout: time.Duration(5000000000),
		Dial: (net.DialFunc)(0x0000000000000000),
		Lookup: (egressselector.Lookup)(0x0000000000000000)
	},
	KubernetesServiceNodePort: 0,
	MaxConnectionBytesPerSec: 0,
	ServiceClusterIPRanges: "",
	PrimaryServiceClusterIPRange: net.IPNet {
		IP: net.IP(nil),
		Mask: net.IPMask(nil)
	},
	SecondaryServiceClusterIPRange: net.IPNet {
		IP: net.IP(nil),
		Mask: net.IPMask(nil)
	},
	ServiceNodePortRange: net.PortRange {
		Base: 30000,
		Size: 2768
	},
	SSHKeyfile: "",
	SSHUser: "",
	ProxyClientCertFile: "",
	ProxyClientKeyFile: "",
	EnableAggregatorRouting: false,
	MasterCount: 1,
	EndpointReconcilerType: "lease",
	ServiceAccountSigningKeyFile: "",
	ServiceAccountIssuer: serviceaccount.TokenGenerator(nil),
	ServiceAccountTokenMaxExpiration: time.Duration(0),
	ShowHiddenMetricsForVersion: ""
}
```

进程启动后，在k8s.io\Kubernetes\cmd\kube-apiserver\apiserver.go中

```
	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
```

该函数最终在k8s.io\Kubernetes\vendor\github.com\spf13\cobra\command.go中调用RunE

```
	if err := c.validateRequiredFlags(); err != nil {
		return err
	}
	if c.RunE != nil {
		if err := c.RunE(c, argWoFlags); err != nil {
			return err
		}
	} else {
		c.Run(c, argWoFlags)
	}
```

RunE函数就是初始化中定义的

```
RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()
			cliflag.PrintFlags(cmd.Flags())
			// set default options
			fileName3 := "/root/debug55.log"
			logFile3,err  := os.Create(fileName3)
			defer logFile3.Close()
			if err != nil {
				log.Fatalln("open file error !")
			}
			completedOptions, err := Complete(s)
			if err != nil {
				return err
			}

			// validate options
			if errs := completedOptions.Validate(); len(errs) != 0 {
				return utilerrors.NewAggregate(errs)
			}

			return Run(completedOptions, genericapiserver.SetupSignalHandler())
		},
		Args: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				if len(arg) > 0 {
					return fmt.Errorf("%q does not take any arguments, got %q", cmd.CommandPath(), args)
				}
			}
			return nil
		},
	}
```

此时我们将s打印出来如下

```
( * options.ServerRunOptions) {
	GenericServerRunOptions: ( * options.ServerRunOptions) {
		AdvertiseAddress: net.IP(nil),
		CorsAllowedOriginList: [] string {
			"/127.0.0.1(:[0-9]+)?$",
			"/localhost(:[0-9]+)?$"
		},
		ExternalHost: "localhost",
		MaxRequestsInFlight: 400,
		MaxMutatingRequestsInFlight: 200,
		RequestTimeout: time.Duration(60000000000),
		GoawayChance: 0,
		LivezGracePeriod: time.Duration(0),
		MinRequestTimeout: 1800,
		ShutdownDelayDuration: time.Duration(0),
		JSONPatchMaxCopyBytes: 3145728,
		MaxRequestBodyBytes: 3145728,
		EnablePriorityAndFairness: true
	},
	Etcd: ( * options.EtcdOptions) {
		StorageConfig: storagebackend.Config {
			Type: "etcd3",
			Prefix: "/registry",
			Transport: storagebackend.TransportConfig {
				ServerList: [] string {
					"http://127.0.0.1:2379"
				},
				KeyFile: "",
				CertFile: "",
				TrustedCAFile: "",
				EgressLookup: (egressselector.Lookup)(0x0000000000000000)
			},
			Paging: true,
			Codec: runtime.Codec(nil),
			EncodeVersioner: runtime.GroupVersioner(nil),
			Transformer: value.Transformer(nil),
			CompactionInterval: time.Duration(300000000000),
			CountMetricPollPeriod: time.Duration(60000000000),
			DBMetricPollInterval: time.Duration(30000000000)
		},
		EncryptionProviderConfigFilepath: "",
		EtcdServersOverrides: [] string(nil),
		DefaultStorageMediaType: "application/vnd.kubernetes.protobuf",
		DeleteCollectionWorkers: 1,
		EnableGarbageCollection: true,
		EnableWatchCache: true,
		DefaultWatchCacheSize: 100,
		WatchCacheSizes: [] string(nil)
	},
	SecureServing: ( * options.SecureServingOptionsWithLoopback) {
		SecureServingOptions: ( * options.SecureServingOptions) {
			BindAddress: net.IP {
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				255,
				255,
				0,
				0,
				0,
				0
			},
			BindPort: 6443,
			BindNetwork: "",
			Required: true,
			ExternalAddress: net.IP(nil),
			Listener: net.Listener(nil),
			ServerCert: options.GeneratableKeyCert {
				CertKey: options.CertKey {
					CertFile: "/var/run/kubernetes/serving-kube-apiserver.crt",
					KeyFile: "/var/run/kubernetes/serving-kube-apiserver.key"
				},
				CertDirectory: "/var/run/kubernetes",
				PairName: "apiserver",
				GeneratedCert: dynamiccertificates.CertKeyContentProvider(nil),
				FixtureDirectory: ""
			},
			SNICertKeys: [] flag.NamedCertKey(nil),
			CipherSuites: [] string(nil),
			MinTLSVersion: "",
			HTTP2MaxStreamsPerConnection: 0,
			PermitPortSharing: false
		}
	},
	InsecureServing: ( * options.DeprecatedInsecureServingOptionsWithLoopback) {
		DeprecatedInsecureServingOptions: ( * options.DeprecatedInsecureServingOptions) {
			BindAddress: net.IP {
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				255,
				255,
				127,
				0,
				0,
				1
			},
			BindPort: 8080,
			BindNetwork: "",
			Listener: net.Listener(nil),
			ListenFunc: (func(string, string, net.ListenConfig)(net.Listener, int, error))(0x0000000000000000)
		}
	},
	Audit: ( * options.AuditOptions) {
		PolicyFile: "/tmp/kube-audit-policy-file",
		LogOptions: options.AuditLogOptions {
			Path: "/tmp/kube-apiserver-audit.log",
			MaxAge: 0,
			MaxBackups: 0,
			MaxSize: 0,
			Format: "json",
			BatchOptions: options.AuditBatchOptions {
				Mode: "blocking",
				BatchConfig: buffered.BatchConfig {
					BufferSize: 10000,
					MaxBatchSize: 1,
					MaxBatchWait: time.Duration(0),
					ThrottleEnable: false,
					ThrottleQPS: 0,
					ThrottleBurst: 0,
					AsyncDelegate: false
				}
			},
			TruncateOptions: options.AuditTruncateOptions {
				Enabled: false,
				TruncateConfig: truncate.Config {
					MaxEventSize: 102400,
					MaxBatchSize: 10485760
				}
			},
			GroupVersionString: "audit.k8s.io/v1"
		},
		WebhookOptions: options.AuditWebhookOptions {
			ConfigFile: "",
			InitialBackoff: time.Duration(10000000000),
			BatchOptions: options.AuditBatchOptions {
				Mode: "batch",
				BatchConfig: buffered.BatchConfig {
					BufferSize: 10000,
					MaxBatchSize: 400,
					MaxBatchWait: time.Duration(30000000000),
					ThrottleEnable: true,
					ThrottleQPS: 10,
					ThrottleBurst: 15,
					AsyncDelegate: true
				}
			},
			TruncateOptions: options.AuditTruncateOptions {
				Enabled: false,
				TruncateConfig: truncate.Config {
					MaxEventSize: 102400,
					MaxBatchSize: 10485760
				}
			},
			GroupVersionString: "audit.k8s.io/v1"
		}
	},
	Features: ( * options.FeatureOptions) {
		EnableProfiling: true,
		EnableContentionProfiling: false
	},
	Admission: ( * options.AdmissionOptions) {
		GenericAdmission: ( * options.AdmissionOptions) {
			RecommendedPluginOrder: [] string {
				"AlwaysAdmit",
				"NamespaceAutoProvision",
				"NamespaceLifecycle",
				"NamespaceExists",
				"SecurityContextDeny",
				"LimitPodHardAntiAffinityTopology",
				"LimitRanger",
				"ServiceAccount",
				"NodeRestriction",
				"TaintNodesByCondition",
				"AlwaysPullImages",
				"ImagePolicyWebhook",
				"PodSecurityPolicy",
				"PodNodeSelector",
				"Priority",
				"DefaultTolerationSeconds",
				"PodTolerationRestriction",
				"DenyEscalatingExec",
				"DenyExecOnPrivileged",
				"EventRateLimit",
				"ExtendedResourceToleration",
				"PersistentVolumeLabel",
				"DefaultStorageClass",
				"StorageObjectInUseProtection",
				"OwnerReferencesPermissionEnforcement",
				"PersistentVolumeClaimResize",
				"RuntimeClass",
				"CertificateApproval",
				"CertificateSigning",
				"CertificateSubjectRestriction",
				"DefaultIngressClass",
				"MutatingAdmissionWebhook",
				"ValidatingAdmissionWebhook",
				"ResourceQuota",
				"AlwaysDeny"
			},
			DefaultOffPlugins: sets.String {
				"AlwaysAdmit": sets.Empty {},
				"AlwaysDeny": sets.Empty {},
				"AlwaysPullImages": sets.Empty {},
				"DenyEscalatingExec": sets.Empty {},
				"DenyExecOnPrivileged": sets.Empty {},
				"EventRateLimit": sets.Empty {},
				"ExtendedResourceToleration": sets.Empty {},
				"ImagePolicyWebhook": sets.Empty {},
				"LimitPodHardAntiAffinityTopology": sets.Empty {},
				"NamespaceAutoProvision": sets.Empty {},
				"NamespaceExists": sets.Empty {},
				"NodeRestriction": sets.Empty {},
				"OwnerReferencesPermissionEnforcement": sets.Empty {},
				"PersistentVolumeLabel": sets.Empty {},
				"PodNodeSelector": sets.Empty {},
				"PodSecurityPolicy": sets.Empty {},
				"PodTolerationRestriction": sets.Empty {},
				"SecurityContextDeny": sets.Empty {}
			},
			EnablePlugins: [] string {
				"NamespaceLifecycle",
				"LimitRanger",
				"ServiceAccount",
				"DefaultStorageClass",
				"DefaultTolerationSeconds",
				"Priority",
				"MutatingAdmissionWebhook",
				"ValidatingAdmissionWebhook",
				"ResourceQuota"
			},
			DisablePlugins: [] string {},
			ConfigFile: "",
			Plugins: ( * admission.Plugins) {
				lock: sync.Mutex {
					state: 0,
					sema: 0
				},
				registry: map[string](admission.Factory) {
					"AlwaysAdmit": (admission.Factory)(0x00000000032dd720),
					"AlwaysDeny": (admission.Factory)(0x00000000032ec9e0),
					"AlwaysPullImages": (admission.Factory)(0x00000000032ddfa0),
					"CertificateApproval": (admission.Factory)(0x00000000032e2b80),
					"CertificateSigning": (admission.Factory)(0x00000000032e38e0),
					"CertificateSubjectRestriction": (admission.Factory)(0x00000000032e4360),
					"DefaultIngressClass": (admission.Factory)(0x00000000032eb7a0),
					"DefaultStorageClass": (admission.Factory)(0x00000000033634a0),
					"DefaultTolerationSeconds": (admission.Factory)(0x00000000032ec440),
					"DenyEscalatingExec": (admission.Factory)(0x00000000032f2580),
					"DenyExecOnPrivileged": (admission.Factory)(0x00000000032f2740),
					"EventRateLimit": (admission.Factory)(0x00000000032f1740),
					"ExtendedResourceToleration": (admission.Factory)(0x00000000032f3500),
					"ImagePolicyWebhook": (admission.Factory)(0x0000000003304380),
					"LimitPodHardAntiAffinityTopology": (admission.Factory)(0x00000000032dec60),
					"LimitRanger": (admission.Factory)(0x000000000330d280),
					"MutatingAdmissionWebhook": (admission.Factory)(0x00000000019ba940),
					"NamespaceAutoProvision": (admission.Factory)(0x000000000330e0c0),
					"NamespaceExists": (admission.Factory)(0x000000000330ed00),
					"NamespaceLifecycle": (admission.Factory)(0x0000000001987ec0),
					"NodeRestriction": (admission.Factory)(0x0000000003320080),
					"OwnerReferencesPermissionEnforcement": (admission.Factory)(0x00000000032f5980),
					"PersistentVolumeClaimResize": (admission.Factory)(0x0000000003361e80),
					"PersistentVolumeLabel": (admission.Factory)(0x0000000003361220),
					"PodNodeSelector": (admission.Factory)(0x0000000003322ba0),
					"PodSecurityPolicy": (admission.Factory)(0x00000000033465e0),
					"PodTolerationRestriction": (admission.Factory)(0x0000000003328d80),
					"Priority": (admission.Factory)(0x000000000332aae0),
					"ResourceQuota": (admission.Factory)(0x0000000003371580),
					"RuntimeClass": (admission.Factory)(0x000000000332ebe0),
					"SecurityContextDeny": (admission.Factory)(0x0000000003347be0),
					"ServiceAccount": (admission.Factory)(0x000000000334c620),
					"StorageObjectInUseProtection": (admission.Factory)(0x0000000003364260),
					"TaintNodesByCondition": (admission.Factory)(0x0000000003320e60),
					"ValidatingAdmissionWebhook": (admission.Factory)(0x00000000019bdfc0)
				}
			},
			Decorators: admission.Decorators {
				(admission.DecoratorFunc)(0x00000000019955e0)
			}
		},
		PluginNames: [] string(nil)
	},
	Authentication: ( * options.BuiltInAuthenticationOptions) {
		APIAudiences: [] string(nil),
		Anonymous: ( * options.AnonymousAuthenticationOptions) {
			Allow: true
		},
		BootstrapToken: ( * options.BootstrapTokenAuthenticationOptions) {
			Enable: false
		},
		ClientCert: ( * options.ClientCertAuthenticationOptions) {
			ClientCA: "/var/run/kubernetes/client-ca.crt",
			CAContentProvider: dynamiccertificates.CAContentProvider(nil)
		},
		OIDC: ( * options.OIDCAuthenticationOptions) {
			CAFile: "",
			ClientID: "",
			IssuerURL: "",
			UsernameClaim: "sub",
			UsernamePrefix: "",
			GroupsClaim: "",
			GroupsPrefix: "",
			SigningAlgs: [] string {
				"RS256"
			},
			RequiredClaims: map[string] string(nil)
		},
		RequestHeader: ( * options.RequestHeaderAuthenticationOptions) {
			ClientCAFile: "/var/run/kubernetes/request-header-ca.crt",
			UsernameHeaders: [] string {
				"X-Remote-User"
			},
			GroupHeaders: [] string {
				"X-Remote-Group"
			},
			ExtraHeaderPrefixes: [] string {
				"X-Remote-Extra-"
			},
			AllowedNames: [] string {
				"system:auth-proxy"
			}
		},
		ServiceAccounts: ( * options.ServiceAccountAuthenticationOptions) {
			KeyFiles: [] string {
				"/tmp/kube-serviceaccount.key"
			},
			Lookup: true,
			Issuer: "https://kubernetes.default.svc",
			JWKSURI: "",
			MaxExpiration: time.Duration(0),
			ExtendExpiration: false
		},
		TokenFile: ( * options.TokenFileAuthenticationOptions) {
			TokenFile: ""
		},
		WebHook: ( * options.WebHookAuthenticationOptions) {
			ConfigFile: "",
			Version: "v1beta1",
			CacheTTL: time.Duration(120000000000)
		},
		TokenSuccessCacheTTL: time.Duration(10000000000),
		TokenFailureCacheTTL: time.Duration(0)
	},
	Authorization: ( * options.BuiltInAuthorizationOptions) {
		Modes: [] string {
			"Node",
			"RBAC"
		},
		PolicyFile: "",
		WebhookConfigFile: "",
		WebhookVersion: "v1beta1",
		WebhookCacheAuthorizedTTL: time.Duration(300000000000),
		WebhookCacheUnauthorizedTTL: time.Duration(30000000000)
	},
	CloudProvider: ( * options.CloudProviderOptions) {
		CloudConfigFile: "",
		CloudProvider: ""
	},
	APIEnablement: ( * options.APIEnablementOptions) {
		RuntimeConfig: flag.ConfigurationMap {}
	},
	EgressSelector: ( * options.EgressSelectorOptions) {
		ConfigFile: ""
	},
	Metrics: ( * metrics.Options) {
		ShowHiddenMetricsForVersion: ""
	},
	Logs: ( * logs.Options) {
		LogFormat: "text"
	},
	AllowPrivileged: false,
	EnableLogsHandler: true,
	EventTTL: time.Duration(3600000000000),
	KubeletConfig: client.KubeletClientConfig {
		Port: 10250,
		ReadOnlyPort: 10255,
		PreferredAddressTypes: [] string {
			"Hostname",
			"InternalDNS",
			"InternalIP",
			"ExternalDNS",
			"ExternalIP"
		},
		TLSClientConfig: rest.TLSClientConfig {
			Insecure: false,
			ServerName: "",
			CertFile: "/var/run/kubernetes/client-kube-apiserver.crt",
			KeyFile: "/var/run/kubernetes/client-kube-apiserver.key",
			CAFile: "",
			CertData: [] uint8(nil),
			KeyData: [] uint8(nil),
			CAData: [] uint8(nil),
			NextProtos: [] string(nil)
		},
		BearerToken: "",
		HTTPTimeout: time.Duration(5000000000),
		Dial: (net.DialFunc)(0x0000000000000000),
		Lookup: (egressselector.Lookup)(0x0000000000000000)
	},
	KubernetesServiceNodePort: 0,
	MaxConnectionBytesPerSec: 0,
	ServiceClusterIPRanges: "10.0.0.0/24",
	PrimaryServiceClusterIPRange: net.IPNet {
		IP: net.IP(nil),
		Mask: net.IPMask(nil)
	},
	SecondaryServiceClusterIPRange: net.IPNet {
		IP: net.IP(nil),
		Mask: net.IPMask(nil)
	},
	ServiceNodePortRange: net.PortRange {
		Base: 30000,
		Size: 2768
	},
	SSHKeyfile: "",
	SSHUser: "",
	ProxyClientCertFile: "/var/run/kubernetes/client-auth-proxy.crt",
	ProxyClientKeyFile: "/var/run/kubernetes/client-auth-proxy.key",
	EnableAggregatorRouting: false,
	MasterCount: 1,
	EndpointReconcilerType: "lease",
	ServiceAccountSigningKeyFile: "/tmp/kube-serviceaccount.key",
	ServiceAccountIssuer: serviceaccount.TokenGenerator(nil),
	ServiceAccountTokenMaxExpiration: time.Duration(0),
	ShowHiddenMetricsForVersion: ""
}
```

通过比较2次s参数打印结果发现

```
第一次打印
	AdvertiseAddress: net.IP(nil),
		CorsAllowedOriginList: [] string(nil),
		ExternalHost: "",
		MaxRequestsInFlight: 400,
		MaxMutatingRequestsInFlight: 200,
		RequestTimeout: time.Duration(60000000000),
		GoawayChance: 0,
		LivezGracePeriod: time.Duration(0),
		MinRequestTimeout: 1800,
		ShutdownDelayDuration: time.Duration(0),
		JSONPatchMaxCopyBytes: 3145728,
		MaxRequestBodyBytes: 3145728,
		EnablePriorityAndFairness: true
第二次打印
( * options.ServerRunOptions) {
	GenericServerRunOptions: ( * options.ServerRunOptions) {
		AdvertiseAddress: net.IP(nil),
		CorsAllowedOriginList: [] string {
			"/127.0.0.1(:[0-9]+)?$",
			"/localhost(:[0-9]+)?$"
		},
		ExternalHost: "localhost",
		MaxRequestsInFlight: 400,
		MaxMutatingRequestsInFlight: 200,
		RequestTimeout: time.Duration(60000000000),
		GoawayChance: 0,
		LivezGracePeriod: time.Duration(0),
		MinRequestTimeout: 1800,
		ShutdownDelayDuration: time.Duration(0),
		JSONPatchMaxCopyBytes: 3145728,
		MaxRequestBodyBytes: 3145728,
		EnablePriorityAndFairness: true
```

这里值比较一部分参数值，例如：

```
		CorsAllowedOriginList: [] string {
			"/127.0.0.1(:[0-9]+)?$",
			"/localhost(:[0-9]+)?$"
		}
CorsAllowedOriginList参数值正是kube-apiserver启动参数中的

--cors-allowed-origins=/127.0.0.1(:[0-9]+)?$,/localhost(:[0-9]+)?$

```

再比如etcd:

```
	Etcd: ( * options.EtcdOptions) {
		StorageConfig: storagebackend.Config {
			Type: "etcd3",
			Prefix: "/registry",
			Transport: storagebackend.TransportConfig {
				ServerList: [] string {
					"http://127.0.0.1:2379"
				},
				KeyFile: "",
				CertFile: "",
				TrustedCAFile: "",
				EgressLookup: (egressselector.Lookup)(0x0000000000000000)
			},
			Paging: true,
			Codec: runtime.Codec(nil),
			EncodeVersioner: runtime.GroupVersioner(nil),
			Transformer: value.Transformer(nil),
			CompactionInterval: time.Duration(300000000000),
			CountMetricPollPeriod: time.Duration(60000000000),
			DBMetricPollInterval: time.Duration(30000000000)
		},

可以看到启动参数etcd --advertise-client-urls http://127.0.0.1:2379
的值被传递
```



其他参数可根据启动参数逐一比较，上面已经打印出s传参前后的值。

从这里开始，s变量搜集到命令行参数传递的值

下面接着分析comelete函数

```
RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()
			cliflag.PrintFlags(cmd.Flags())
			completedOptions, err := Complete(s)
			if err != nil {
				return err
			}

			// validate options
			if errs := completedOptions.Validate(); len(errs) != 0 {
				return utilerrors.NewAggregate(errs)
			}

			return Run(completedOptions, genericapiserver.SetupSignalHandler())
		},
		Args: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				if len(arg) > 0 {
					return fmt.Errorf("%q does not take any arguments, got %q", cmd.CommandPath(), args)
				}
			}
			return nil
		},
	}
```





