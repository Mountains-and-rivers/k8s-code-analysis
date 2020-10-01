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

NewServerRunOptions的初始化为一个空值

```
 app.completedServerRunOptions{ServerRunOptions:(*options.ServerRunOptions)(nil)}
```

可以看到这个结构体没有初始值

```
	if err := s.GenericServerRunOptions.DefaultAdvertiseAddress(s.SecureServing.SecureServingOptions); err != nil {
		return options, err
	}

	if err := kubeoptions.DefaultAdvertiseAddress(s.GenericServerRunOptions, s.InsecureServing.DeprecatedInsecureServingOptions); err != nil {
		return options, err
	}
```

https://kubernetes.io/zh/docs/reference/command-line-tools-reference/kube-apiserver/

```
第一个分支主要校验了https访问的参数
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
	}
--enable-secure-port用于监听具有认证授权功能的 HTTPS 协议的端口。如果为 0，则不会监听 HTTPS 协议。 （默认值 6443)
```

第二个分支主要校验了http访问的参数

```
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
	}
--insecure-port 用于监听不安全和为认证访问的端口。这个配置假设你已经设置了防火墙规则，使得这个端口不能从集群外访问。对集群的公共地址的 443 端口的访问将被代理到这个端口。默认设置中使用 nginx 实现。（默认值 8080）
```

```
apiServerServiceIP, primaryServiceIPRange, secondaryServiceIPRange, err := getServiceIPAndRanges(s.ServiceClusterIPRanges)

apiServerServiceIP取集群范围的第一个ip

参数指定:--service-cluster-ip-range=10.0.0.0/24

这个pod不是api创建的，也叫静态pod，无法删除

[root@MiWiFi-RM2100-srv ~]# kubectl get service
NAME         TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
kubernetes   ClusterIP   10.0.0.1     <none>        443/TCP   7h50m

10.0.0.1是集群内访问ip，不安全的http 8080端口 就是由ClusterIP代理转发请求

kubernetes endpoints 中的 ip 以及 port 可以通过 --advertise-address 和 --secure-port 启动参数来指定

如果不传递，取 --bind-address

[root@MiWiFi-RM2100-srv ~]# kubectl get endpoints kubernetes
NAME         ENDPOINTS             AGE
kubernetes   192.168.31.186:6443   7h54m
```

接着分析

```
func Run(completeOptions completedServerRunOptions, stopCh <-chan struct{}) error {
	// To help debugging, immediately log version
	// 定义一个文件
	server, err := CreateServerChain(completeOptions, stopCh)
	if err != nil {
		return err
	}

	prepared, err := server.PrepareRun()
	if err != nil {
		return err
	}

	return prepared.Run(stopCh)
}
```

CreateServerChain 是完成 server 初始化的方法，里面包含 APIExtensionsServer、KubeAPIServer、AggregatorServer 初始化的所有流程，最终返回 aggregatorapiserver.APIAggregator 实例，初始化流程主要有：http filter chain 的配置、API Group 的注册、http path 与 handler 的关联以及 handler 后端存储 etcd 的配置。其主要逻辑为：

+ 1、调用 CreateKubeAPIServerConfig 创建 KubeAPIServer 所需要的配置，主要是创建 master.Config，其中会调用 buildGenericConfig 生成 genericConfig，genericConfig 中包含 apiserver 的核心配置
+ 2、判断是否启用了扩展的 API server 并调用 createAPIExtensionsConfig 为其创建配置，apiExtensions server 是一个代理服务，用于代理 kubeapiserver 中的其他 server，比如 metric-server；
+ 3、调用 createAPIExtensionsServer 创建 apiExtensionsServer 实例；
+ 4、调用 CreateKubeAPIServer初始化 kubeAPIServer；
+ 5、调用 createAggregatorConfig 为 aggregatorServer 创建配置并调用 createAggregatorServer 初始化 aggregatorServer；
+ 6、配置并判断是否启动非安全的 http server；

```
// CreateServerChain creates the apiservers connected via delegation.
func CreateServerChain(completedOptions completedServerRunOptions, stopCh <-chan struct{}) (*aggregatorapiserver.APIAggregator, error) {
	nodeTunneler, proxyTransport, err := CreateNodeDialer(completedOptions)
	if err != nil {
		return nil, err
	}
	// 1、为 kubeAPIServer 创建配置
	kubeAPIServerConfig, insecureServingInfo, serviceResolver, pluginInitializer, err := CreateKubeAPIServerConfig(completedOptions, nodeTunneler, proxyTransport)
	if err != nil {
		return nil, err
	}
	// 2、判断是否配置了 APIExtensionsServer，创建 apiExtensionsConfig
	// If additional API servers are added, they should be gated.
	apiExtensionsConfig, err := createAPIExtensionsConfig(*kubeAPIServerConfig.GenericConfig, kubeAPIServerConfig.ExtraConfig.VersionedInformers, pluginInitializer, completedOptions.ServerRunOptions, completedOptions.MasterCount,
		serviceResolver, webhook.NewDefaultAuthenticationInfoResolverWrapper(proxyTransport, kubeAPIServerConfig.GenericConfig.EgressSelector, kubeAPIServerConfig.GenericConfig.LoopbackClientConfig))
	if err != nil {
		return nil, err
	}
	// 3、初始化 APIExtensionsServer
	apiExtensionsServer, err := createAPIExtensionsServer(apiExtensionsConfig, genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, err
	}
    // 4、初始化 KubeAPIServer
	kubeAPIServer, err := CreateKubeAPIServer(kubeAPIServerConfig, apiExtensionsServer.GenericAPIServer)
	if err != nil {
		return nil, err
	}
	// 5、创建 AggregatorConfig
	// aggregator comes last in the chain
	aggregatorConfig, err := createAggregatorConfig(*kubeAPIServerConfig.GenericConfig, completedOptions.ServerRunOptions, kubeAPIServerConfig.ExtraConfig.VersionedInformers, serviceResolver, proxyTransport, pluginInitializer)
	if err != nil {
		return nil, err
	}
	 // 6、初始化 AggregatorServer
	aggregatorServer, err := createAggregatorServer(aggregatorConfig, kubeAPIServer.GenericAPIServer, apiExtensionsServer.Informers)
	if err != nil {
		// we don't need special handling for innerStopCh because the aggregator server doesn't create any go routines
		return nil, err
	}
	// 7、判断是否启动非安全端口的 http server
	if insecureServingInfo != nil {
		insecureHandlerChain := kubeserver.BuildInsecureHandlerChain(aggregatorServer.GenericAPIServer.UnprotectedHandler(), kubeAPIServerConfig.GenericConfig)
		if err := insecureServingInfo.Serve(insecureHandlerChain, kubeAPIServerConfig.GenericConfig.RequestTimeout, stopCh); err != nil {
			return nil, err
		}
	}

	return aggregatorServer, nil
}
```

打印`kubeAPIServerConfig`如下

```
{
	GenericConfig: server.Config {
		SecureServing: ( * server.SecureServingInfo)(0xc0005f0100),
		Authentication: server.AuthenticationInfo {
			APIAudiences: authenticator.Audiences {
				"https://kubernetes.default.svc"
			},
			Authenticator: ( * union.unionAuthRequestHandler)(0xc0007c64a0)
		},
		Authorization: server.AuthorizationInfo {
			Authorizer: union.unionAuthzHandler {
				( * node.NodeAuthorizer)(0xc00051de40), ( * rbac.RBACAuthorizer)(0xc000430150)
			}
		},
		LoopbackClientConfig: & rest.Config {
			Host: "https://[::1]:6443",
			APIPath: "",
			ContentConfig: rest.ContentConfig {
				AcceptContentTypes: "",
				ContentType: "application/vnd.kubernetes.protobuf",
				GroupVersion: ( * schema.GroupVersion)(nil),
				NegotiatedSerializer: runtime.NegotiatedSerializer(nil)
			},
			Username: "",
			Password: "",
			BearerToken: "--- REDACTED ---",
			BearerTokenFile: "",
			Impersonate: rest.ImpersonationConfig {
				UserName: "",
				Groups: [] string(nil),
				Extra: map[string][] string(nil)
			},
			AuthProvider: < nil > ,
			AuthConfigPersister: rest.AuthProviderConfigPersister(nil),
			ExecProvider: < nil > ,
			TLSClientConfig: rest.sanitizedTLSClientConfig {
				Insecure: false,
				ServerName: "apiserver-loopback-client",
				CertFile: "",
				KeyFile: "",
				CAFile: "",
				CertData: [] uint8(nil),
				KeyData: [] uint8(nil),
				CAData: [] uint8 {
					0x2d,
					...
					0x2d,
					0x2d,
					0xa
				},
				NextProtos: [] string(nil)
			},
			UserAgent: "",
			DisableCompression: true,
			RateLimiter: flowcontrol.RateLimiter(nil),
			WarningHandler: rest.WarningHandler(nil),
			Timeout: 0,
			Dial: (func(context.Context, string, string)(net.Conn, error))(nil),
			Proxy: (func( * http.Request)( * url.URL, error))(nil)
		},
		EgressSelector: ( * egressselector.EgressSelector)(nil),
		RuleResolver: union.unionAuthzRulesHandler {
			( * node.NodeAuthorizer)(0xc00051de40), ( * rbac.RBACAuthorizer)(0xc000430150)
		},
		AdmissionControl: ( * metrics.pluginHandlerWithMetrics)(0xc000db4840),
		CorsAllowedOriginList: [] string {
			"/127.0.0.1(:[0-9]+)?$",
			"/localhost(:[0-9]+)?$"
		},
		FlowControl: flowcontrol.Interface(nil),
		EnableIndex: true,
		EnableProfiling: true,
		EnableDiscovery: true,
		EnableContentionProfiling: false,
		EnableMetrics: true,
		DisabledPostStartHooks: sets.String {},
		PostStartHooks: map[string] server.PostStartHookConfigEntry {
			{
				"start-kube-apiserver-admission-initializer": server.PostStartHookConfigEntry {
					hook: (server.PostStartHookFunc)(0x3361f60),
					originatingStack: "goroutine 1 [running]:\nruntime/debug.Stack(0x3fb4700............."

				}
			}
		},
		Version: ( * version.Info)(0xc0007d4bd0),
		AuditBackend: ( * options.ignoreErrorsBackend)(0xc000d38560),
		AuditPolicyChecker: ( * policy.policyChecker)(0xc0002fcdc0),
		ExternalAddress: "localhost",
		BuildHandlerChainFunc: (func(http.Handler, * server.Config) http.Handler)(0x19c6100),
		HandlerChainWaitGroup: ( * waitgroup.SafeWaitGroup)(0xc0001ba210),
		DiscoveryAddresses: discovery.Addresses(nil),
		HealthzChecks: [] healthz.HealthChecker {
			healthz.ping {}, ( * healthz.log)(0x71e9440), ( * healthz.healthzCheck)(0xc000237a00)
		},
		LivezChecks: [] healthz.HealthChecker {
			healthz.ping {}, ( * healthz.log)(0x71e9440), ( * healthz.healthzCheck)(0xc000237a00)
		},
		ReadyzChecks: [] healthz.HealthChecker {
			healthz.ping {}, ( * healthz.log)(0x71e9440), ( * healthz.healthzCheck)(0xc000237a00)
		},
		LegacyAPIGroupPrefixes: sets.String {
			"/api": sets.Empty {}
		},
		RequestInfoResolver: request.RequestInfoResolver(nil),
		Serializer: serializer.CodecFactory {
			scheme: ( * runtime.Scheme)(0xc0005503f0),
			universal: ( * recognizer.decoder)(0xc0007c6a80),
			accepts: [] runtime.SerializerInfo {
				runtime.SerializerInfo {
					MediaType: "application/json",
					MediaTypeType: "application",
					MediaTypeSubType: "json",
					EncodesAsText: true,
					Serializer: ( * json.Serializer)(0xc000568280),
					PrettySerializer: ( * json.Serializer)(0xc000568320),
					StreamSerializer: ( * runtime.StreamSerializerInfo)(0xc0005a6900)
				}, runtime.SerializerInfo {
					MediaType: "application/yaml",
					MediaTypeType: "application",
					MediaTypeSubType: "yaml",
					EncodesAsText: true,
					Serializer: ( * json.Serializer)(0xc0005683c0),
					PrettySerializer: runtime.Serializer(nil),
					StreamSerializer: ( * runtime.StreamSerializerInfo)(nil)
				}, runtime.SerializerInfo {
					MediaType: "application/vnd.kubernetes.protobuf",
					MediaTypeType: "application",
					MediaTypeSubType: "vnd.kubernetes.protobuf",
					EncodesAsText: false,
					Serializer: ( * protobuf.Serializer)(0xc000146400),
					PrettySerializer: runtime.Serializer(nil),
					StreamSerializer: ( * runtime.StreamSerializerInfo)(0xc0005a6990)
				}
			},
			legacySerializer: ( * json.Serializer)(0xc000568280)
		},
		OpenAPIConfig: ( * common.Config)(0xc0007d4630),
		RESTOptionsGetter: ( * options.StorageFactoryRestOptionsFactory)(0xc0005e6640),
		RequestTimeout: 60000000000,
		MinRequestTimeout: 1800,
		LivezGracePeriod: 0,
		ShutdownDelayDuration: 0,
		JSONPatchMaxCopyBytes: 3145728,
		MaxRequestBodyBytes: 3145728,
		MaxRequestsInFlight: 400,
		MaxMutatingRequestsInFlight: 200,
		LongRunningFunc: (request.LongRunningRequestCheck)(0x18c25c0),
		GoawayChance: 0,
		MergedResourceConfig: ( * storage.ResourceConfig)(0xc0002e4b60),
		PublicAddress: net.IP {
			0x0,
			0x0,
			0x0,
			0x0,
			0x0,
			0x0,
			0x0,
			0x0,
			0x0,
			0x0,
			0xff,
			0xff,
			0xc0,
			0xa8,
			0x1f,
			0xba
		},
		EquivalentResourceRegistry: runtime.EquivalentResourceRegistry(nil)
	}
	ExtraConfig: controlplane.ExtraConfig {
		ClusterAuthenticationInfo: clusterauthenticationtrust.ClusterAuthenticationInfo {
			ClientCA: ( * dynamiccertificates.DynamicFileCAContent)(0xc0002f4de0),
			RequestHeaderUsernameHeaders: headerrequest.StaticStringSlice {
				"X-Remote-User"
			},
			RequestHeaderGroupHeaders: headerrequest.StaticStringSlice {
				"X-Remote-Group"
			},
			RequestHeaderExtraHeaderPrefixes: headerrequest.StaticStringSlice {
				"X-Remote-Extra-"
			},
			RequestHeaderAllowedNames: headerrequest.StaticStringSlice {
				"system:auth-proxy"
			},
			RequestHeaderCA: ( * dynamiccertificates.DynamicFileCAContent)(0xc0002f50e0)
		},
		APIResourceConfigSource: ( * storage.ResourceConfig)(0xc0006c4d70),
		StorageFactory: ( * storage.DefaultStorageFactory)(0xc00056a6c0),
		EndpointReconcilerConfig: controlplane.EndpointReconcilerConfig {
			Reconciler: reconcilers.EndpointReconciler(nil),
			Interval: 0
		},
		EventTTL: 3600000000000,
		KubeletClientConfig: rest.sanitizedTLSClientConfig {
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
		Tunneler: tunneler.Tunneler(nil),
		EnableLogsSupport: true,
		ProxyTransport: ( * http.Transport)(0xc000615a40),
		ServiceIPRange: net.IPNet {
			IP: net.IP {
				0xa,
				0x0,
				0x0,
				0x0
			},
			Mask: net.IPMask {
				0xff,
				0xff,
				0xff,
				0x0
			}
		},
		APIServerServiceIP: net.IP {
			0x0,
			0x0,
			0x0,
			0x0,
			0x0,
			0x0,
			0x0,
			0x0,
			0x0,
			0x0,
			0xff,
			0xff,
			0xa,
			0x0,
			0x0,
			0x1
		},
		SecondaryServiceIPRange: net.IPNet {
			IP: net.IP(nil),
			Mask: net.IPMask(nil)
		},
		SecondaryAPIServerServiceIP: net.IP(nil),
		APIServerServicePort: 443,
		ServiceNodePortRange: net.PortRange {
			Base: 30000,
			Size: 2768
		},
		ExtraServicePorts: [] v1.ServicePort(nil),
		ExtraEndpointPorts: [] v1.EndpointPort(nil),
		KubernetesServiceNodePort: 0,
		MasterCount: 1,
		MasterEndpointReconcileTTL: 0,
		EndpointReconcilerType: "lease",
		ServiceAccountIssuer: ( * serviceaccount.jwtTokenGenerator)(0xc000b30160),
		ServiceAccountMaxExpiration: 0,
		ExtendExpiration: false,
		ServiceAccountIssuerURL: "https://kubernetes.default.svc",
		ServiceAccountJWKSURI: "",
		ServiceAccountPublicKeys: [] interface {} {
			( * rsa.PublicKey)(0xc0002f5260)
		},
		VersionedInformers: ( * informers.sharedInformerFactory)(0xc000c05130)
	}
}
```

打印`insecureServingInfo`如下

```
( * server.DeprecatedInsecureServingInfo) {
	Listener: ( * net.TCPListener) {
		fd: ( * net.netFD) {
			pfd: poll.FD {
				fdmu: poll.fdMutex {
					state: 0,
					rsema: 0,
					wsema: 0
				},
				Sysfd: 9,
				pd: poll.pollDesc {
					runtimeCtx: 140281080610648
				},
				iovecs: ( * [] syscall.Iovec)(nil),
				csema: 0,
				isBlocking: 0,
				IsStream: true,
				ZeroReadIsEOF: true,
				isFile: false
			},
			family: 2,
			sotype: 1,
			isConnected: false,
			net: "tcp",
			laddr: ( * net.TCPAddr) {
				IP: net.IP {
					127,
					0,
					0,
					1
				},
				Port: 8080,
				Zone: ""
			},
			raddr: net.Addr(nil)
		},
		lc: net.ListenConfig {
			Control: (func(string, string, syscall.RawConn) error)(0x0000000000000000),
			KeepAlive: time.Duration(0)
		}
	},
	Name: ""
}
```

打印`serviceResolver`如下

```
( * apiserver.loopbackResolver) {
	delegate: ( * apiserver.aggregatorClusterRouting) {
		services: ( * v1.serviceLister) {
			indexer: ( * cache.cache) {
				cacheStorage: ( * cache.threadSafeMap) {
					lock: sync.RWMutex {
						w: sync.Mutex {
							state: 0,
							sema: 0
						},
						writerSem: 0,
						readerSem: 0,
						readerCount: 0,
						readerWait: 0
					},
					items: map[string] interface {} {},
					indexers: cache.Indexers {
						"namespace": (cache.IndexFunc)(0x0000000001421260)
					},
					indices: cache.Indices {}
				},
				keyFunc: (cache.KeyFunc)(0x000000000141d3c0)
			}
		}
	},
	host: ( * url.URL) {
		Scheme: "https",
		Opaque: "",
		User: ( * url.Userinfo)(nil),
		Host: "[::1]:6443",
		Path: "",
		RawPath: "",
		ForceQuery: false,
		RawQuery: "",
		Fragment: "",
		RawFragment: ""
	}
}
```

打印`pluginInitializer`如下

```
admission.PluginInitializer {
	( * initializer.PluginInitializer) {
		serviceResolver: ( * apiserver.loopbackResolver) {
			delegate: ( * apiserver.aggregatorClusterRouting) {
				services: ( * v1.serviceLister) {
					indexer: ( * cache.cache) {
						cacheStorage: ( * cache.threadSafeMap) {
							lock: sync.RWMutex {
								w: sync.Mutex {
									state: 0,
									sema: 0
								},
								writerSem: 0,
								readerSem: 0,
								readerCount: 0,
								readerWait: 0
							},
							items: map[string] interface {} {},
							indexers: cache.Indexers {
								"namespace": (cache.IndexFunc)(0x0000000001421260)
							},
							indices: cache.Indices {}
						},
						keyFunc: (cache.KeyFunc)(0x000000000141d3c0)
					}
				}
			},
			host: ( * url.URL) {
				Scheme: "https",
				Opaque: "",
				User: ( * url.Userinfo)(nil),
				Host: "[::1]:6443",
				Path: "",
				RawPath: "",
				ForceQuery: false,
				RawQuery: "",
				Fragment: "",
				RawFragment: ""
			}
		},
		authenticationInfoResolverWrapper: (webhook.AuthenticationInfoResolverWrapper)(0x0000000001695160)
	}, ( * admission.PluginInitializer) {
		cloudConfig: [] uint8(nil),
		restMapper: ( * restmapper.DeferredDiscoveryRESTMapper) {
			initMu: sync.Mutex {
				state: 0,
				sema: 0
			},
			delegate: meta.RESTMapper(nil),
			cl: ( * memory.memCacheClient) {
				delegate: ( * discovery.DiscoveryClient) {
					restClient: ( * rest.RESTClient) {
						base: ( * url.URL) {
							Scheme: "https",
							Opaque: "",
							User: ( * url.Userinfo)(nil),
							Host: "[::1]:6443",
							Path: "/",
							RawPath: "",
							ForceQuery: false,
							RawQuery: "",
							Fragment: "",
							RawFragment: ""
						},
						versionedAPIPath: "/",
						content: rest.ClientContentConfig {
							AcceptContentTypes: "",
							ContentType: "application/vnd.kubernetes.protobuf",
							GroupVersion: schema.GroupVersion {
								Group: "meta.k8s.io",
								Version: "v1"
							},
							Negotiator: ( * runtime.clientNegotiator) {
								serializer: ( * serializer.negotiatedSerializerWrapper) {
									info: runtime.SerializerInfo {
										MediaType: "",
										MediaTypeType: "",
										MediaTypeSubType: "",
										EncodesAsText: false,
										Serializer: runtime.NoopEncoder {
											Decoder: ( * versioning.codec) {
												encoder: runtime.Encoder(nil),
												decoder: ( * recognizer.decoder) {
													decoders: [] runtime.Decoder {
														( * json.Serializer) {
															meta: json.SimpleMetaFactory {},
															options: json.SerializerOptions {
																Yaml: false,
																Pretty: false,
																Strict: false
															},
															creater: ( * runtime.Scheme) {
																gvkToType: map[schema.GroupVersionKind] reflect.Type {
																	schema.GroupVersionKind {
																		Group: "",
																		Version: "__internal",
																		Kind: "WatchEvent"
																	}: ( * reflect.rtype) {
																		size: 32,
																		ptrdata: 32,
																		hash: 536910771,
																		tflag: reflect.tflag(7),
																		align: 8,
																		fieldAlign: 8,
																		kind: 25,
																		equal: (func(unsafe.Pointer, unsafe.Pointer) bool)(0x0000000000a4d6e0),
																		gcdata: ( * uint8)(9),
																		str: reflect.nameOff(328796),
																		ptrToThis: reflect.typeOff(8420832)
																	},
													},
													schemeName: "k8s.io/client-go/kubernetes/scheme/register.go:70"
												},
												encodeVersion: runtime.disabledGroupVersioner {},
												decodeVersion: runtime.internalGroupVersioner {},
												identifier: runtime.Identifier("{\"encodeGV\":\"disabled\",\"name\":\"versioning\"}"),
												originalSchemeName: "k8s.io/client-go/kubernetes/scheme/register.go:70"
											}
										},
										PrettySerializer: runtime.Serializer(nil),
										StreamSerializer: ( * runtime.StreamSerializerInfo)(nil)
									}
								},
								encode: schema.GroupVersion {
									Group: "meta.k8s.io",
									Version: "v1"
								},
								decode: runtime.GroupVersioner(nil)
							}
						},
						createBackoffMgr: (func() rest.BackoffManager)(0x0000000001125b20),
						rateLimiter: flowcontrol.RateLimiter(nil),
						warningHandler: rest.WarningHandler(nil),
						Client: ( * http.Client) {
							Transport: ( * transport.userAgentRoundTripper) {
								agent: "kube-apiserver/v1.20.0 (linux/amd64) kubernetes/d9b576d",
								rt: ( * transport.bearerAuthRoundTripper) {
									bearer: "8feec95f-b9a2-477c-aaef-44b43ee27eef",
									source: oauth2.TokenSource(nil),
									rt: ( * http.Transport) {
										idleMu: sync.Mutex {
											state: 0,
											sema: 0
										},
										closeIdle: false,
										idleConn: map[http.connectMethodKey][] * http.persistConn(nil),
										idleConnWait: map[http.connectMethodKey] http.wantConnQueue(nil),
										idleLRU: http.connLRU {
											ll: ( * list.List)(nil),
											m: map[ * http.persistConn] * list.Element(nil)
										},
										reqMu: sync.Mutex {
											state: 0,
											sema: 0
										},
										reqCanceler: map[http.cancelKey](func(error))(nil),
										altMu: sync.Mutex {
											state: 0,
											sema: 0
										},
										altProto: atomic.Value {
											v: map[string] http.RoundTripper {
												"https": http2.noDialH2RoundTripper {
													Transport: ( * http2.Transport) {
														DialTLS: (func(string, string, * tls.Config)(net.Conn, error))(0x0000000000000000),
														TLSClientConfig: ( * tls.Config)(nil),
														ConnPool: http2.noDialClientConnPool {
															clientConnPool: ( * http2.clientConnPool) {
																t: < REC( * http2.Transport) > ,
																mu: sync.Mutex {
																	state: 0,
																	sema: 0
																},
																conns: map[string][] * http2.ClientConn(nil),
																dialing: map[string] * http2.dialCall(nil),
																keys: map[ * http2.ClientConn][] string(nil),
																addConnCalls: map[string] * http2.addConnCall(nil)
															}
														},
														DisableCompression: false,
														AllowHTTP: false,
														MaxHeaderListSize: 0,
														StrictMaxConcurrentStreams: false,
														ReadIdleTimeout: time.Duration(0),
														PingTimeout: time.Duration(0),
														t1: < REC( * http.Transport) > ,
														connPoolOnce: sync.Once {
															done: 0,
															m: sync.Mutex {
																state: 0,
																sema: 0
															}
														},
														connPoolOrDef: http2.ClientConnPool(nil)
													}
												}
											}
										},
										connsPerHostMu: sync.Mutex {
											state: 0,
											sema: 0
										},
										connsPerHost: map[http.connectMethodKey] int(nil),
										connsPerHostWait: map[http.connectMethodKey] http.wantConnQueue(nil),
										Proxy: (func( * http.Request)( * url.URL, error))(0x000000000074ecc0),
										DialContext: (func(context.Context, string, string)(net.Conn, error))(0x000000000076d880),
										Dial: (func(string, string)(net.Conn, error))(0x0000000000000000),
										DialTLSContext: (func(context.Context, string, string)(net.Conn, error))(0x0000000000000000),
										DialTLS: (func(string, string)(net.Conn, error))(0x0000000000000000),
										TLSClientConfig: ( * tls.Config) {
											Rand: io.Reader(nil),
											Time: (func() time.Time)(0x0000000000000000),
											Certificates: [] tls.Certificate(nil),
											NameToCertificate: map[string] * tls.Certificate(nil),
											GetCertificate: (func( * tls.ClientHelloInfo)( * tls.Certificate, error))(0x0000000000000000),
											GetClientCertificate: (func( * tls.CertificateRequestInfo)( * tls.Certificate, error))(0x0000000000000000),
											GetConfigForClient: (func( * tls.ClientHelloInfo)( * tls.Config, error))(0x0000000000000000),
											VerifyPeerCertificate: (func([][] uint8, [][] * x509.Certificate) error)(0x0000000000000000),
											VerifyConnection: (func(tls.ConnectionState) error)(0x0000000000000000),
											RootCAs: ( * x509.CertPool) {
												bySubjectKeyId: map[string][] int {
													"G\\\x9d\xe4N% \xcarhX\x95\xfe_\xa4:\x10\v\x83C": {
														1
													}
												},
												byName: map[string][] int {
													"0/1-0+\x06\x03U\x04\x03\f$apiserver-loopback-client@1601561120": {
														0
													},
													"02100.\x06\x03U\x04\x03\f'apiserver-loopback-client-ca@1601561119": {
														1
													}
												},
												certs: [] * x509.Certificate {
													( * x509.Certificate) {
														Raw: [] uint8 {
															48,
															...
															57
														},
														Signature: [] uint8 {
															77,
															...
															130
														},
														SignatureAlgorithm: x509.SignatureAlgorithm(4),
														PublicKeyAlgorithm: x509.PublicKeyAlgorithm(1),
														PublicKey: ( * rsa.PublicKey) {
															N: ( * big.Int) {
																neg: false,
																abs: big.nat {
																	big.Word(4467047934295439745), big.Word(11804261998188504085), big.Word(12734222686145494324), big.Word(6004240950591159072), big.Word(882613207027485046), big.Word(14219495807891940847), big.Word(16692952319756241792), big.Word(12555223219124596234), big.Word(5808386148688118392), big.Word(4351824634399259595), big.Word(15606215361341365833), big.Word(6991886317574850937), big.Word(17042739855607430902), big.Word(3523126258919069449), big.Word(3541127956405046239), big.Word(7762706889514875739), big.Word(13669838014468849007), big.Word(14115580125646115119), big.Word(16823384174106302912), big.Word(10066265030490221130), big.Word(17508660402187474826), big.Word(10628896456786335437), big.Word(8363142937875929801), big.Word(13298559846561277519), big.Word(10566176761967197124), big.Word(4216649796174161664), big.Word(2381212613559119954), big.Word(8978373921590667864), big.Word(8591362884774836999), big.Word(7799435592285926393), big.Word(4041558672062723736), big.Word(15056655239687372865)
																}
															},
															E: 65537
														},
														Version: 3,
														SerialNumber: ( * big.Int) {
															neg: false,
															abs: big.nat {
																big.Word(2)
															}
														},
														Issuer: pkix.Name {
															Country: [] string(nil),
															Organization: [] string(nil),
															OrganizationalUnit: [] string(nil),
															Locality: [] string(nil),
															Province: [] string(nil),
															StreetAddress: [] string(nil),
															PostalCode: [] string(nil),
															SerialNumber: "",
															CommonName: "apiserver-loopback-client-ca@1601561119",
															Names: [] pkix.AttributeTypeAndValue {
																pkix.AttributeTypeAndValue {
																	Type: asn1.ObjectIdentifier {
																		2,
																		5,
																		4,
																		3
																	},
																	Value: "apiserver-loopback-client-ca@1601561119"
																}
															},
															ExtraNames: [] pkix.AttributeTypeAndValue(nil)
														},
														Subject: pkix.Name {
															Country: [] string(nil),
															Organization: [] string(nil),
															OrganizationalUnit: [] string(nil),
															Locality: [] string(nil),
															Province: [] string(nil),
															StreetAddress: [] string(nil),
															PostalCode: [] string(nil),
															SerialNumber: "",
															CommonName: "apiserver-loopback-client@1601561120",
															Names: [] pkix.AttributeTypeAndValue {
																pkix.AttributeTypeAndValue {
																	Type: asn1.ObjectIdentifier {
																		2,
																		5,
																		4,
																		3
																	},
																	Value: "apiserver-loopback-client@1601561120"
																}
															},
															ExtraNames: [] pkix.AttributeTypeAndValue(nil)
														},
														NotBefore: time.Time {
															wall: 0,
															ext: 63737154319,
															loc: ( * time.Location)(nil)
														},
														NotAfter: time.Time {
															wall: 0,
															ext: 63768690319,
															loc: ( * time.Location)(nil)
														},
														KeyUsage: x509.KeyUsage(5),
														Extensions: [] pkix.Extension {
															pkix.Extension {
																Id: asn1.ObjectIdentifier {
																	2,
																	5,
																	29,
																	15
																},
																Critical: true,
																Value: [] uint8 {
																	3,
																	2,
																	5,
																	160
																}
															}, pkix.Extension {
																Id: asn1.ObjectIdentifier {
																	2,
																	5,
																	29,
																	37
																},
																Critical: false,
																Value: [] uint8 {
																	48,
																	...
																	1
																}
															}, pkix.Extension {
																Id: asn1.ObjectIdentifier {
																	2,
																	5,
																	29,
																	19
																},
																Critical: true,
																Value: [] uint8 {
																	48,
																	0
																}
															}, pkix.Extension {
																Id: asn1.ObjectIdentifier {
																	2,
																	5,
																	29,
																	35
																},
																Critical: false,
																Value: [] uint8 {
																	48,
																	...
																	67
																}
															}, pkix.Extension {
																Id: asn1.ObjectIdentifier {
																	2,
																	5,
																	29,
																	17
																},
																Critical: false,
																Value: [] uint8 {
																	48,
																	...
																}
															}
														},
														ExtraExtensions: [] pkix.Extension(nil),
														UnhandledCriticalExtensions: [] asn1.ObjectIdentifier(nil),
														ExtKeyUsage: [] x509.ExtKeyUsage {
															x509.ExtKeyUsage(1)
														},
														UnknownExtKeyUsage: [] asn1.ObjectIdentifier(nil),
														BasicConstraintsValid: true,
														IsCA: false,
														MaxPathLen: -1,
														MaxPathLenZero: false,
														SubjectKeyId: [] uint8(nil),
														AuthorityKeyId: [] uint8 {
															71,
															....
															67
														},
														OCSPServer: [] string(nil),
														IssuingCertificateURL: [] string(nil),
														DNSNames: [] string {
															"apiserver-loopback-client"
														},
														EmailAddresses: [] string(nil),
														IPAddresses: [] net.IP(nil),
														URIs: [] * url.URL(nil),
														PermittedDNSDomainsCritical: false,
														PermittedDNSDomains: [] string(nil),
														ExcludedDNSDomains: [] string(nil),
														PermittedIPRanges: [] * net.IPNet(nil),
														ExcludedIPRanges: [] * net.IPNet(nil),
														PermittedEmailAddresses: [] string(nil),
														ExcludedEmailAddresses: [] string(nil),
														PermittedURIDomains: [] string(nil),
														ExcludedURIDomains: [] string(nil),
														CRLDistributionPoints: [] string(nil),
														PolicyIdentifiers: [] asn1.ObjectIdentifier(nil)
													}, ( * x509.Certificate) {
														Raw: [] uint8 {
															48,
															...
															67
														},
														RawTBSCertificate: [] uint8 {
															48,
															...
															67
														},
														RawSubjectPublicKeyInfo: [] uint8 {
															48,
															...
															1
														},
														RawSubject: [] uint8 {
															48,
															....
															49,
															57
														},
														RawIssuer: [] uint8 {
															48,
															50,
															....
															67
														},
														SignatureAlgorithm: x509.SignatureAlgorithm(4),
														PublicKeyAlgorithm: x509.PublicKeyAlgorithm(1),
														PublicKey: ( * rsa.PublicKey) {
															N: ( * big.Int) {
																neg: false,
																abs: big.nat {
																	big.Word(15082423401840827497), big.Word(16882044796948421544), big.Word(1532791482459003691), big.Word(4307143165378671072), big.Word(11367010410538378173), big.Word(2181059092902566210), big.Word(16350110199680856087), big.Word(2018587137980962277), big.Word(663969875087615483), big.Word(11413752285868909423), big.Word(6359101557693287169), big.Word(745961809079309987), big.Word(15508723976004398893), big.Word(4538445274422053029), big.Word(395394294817573188), big.Word(14662209200171798742), big.Word(8602824816917978056), big.Word(5473616640342757294), big.Word(11041932401921240298), big.Word(13521534757507651536), big.Word(1054743552012972981), big.Word(17844080866742431816), big.Word(650968815430764172), big.Word(8515624550716625893), big.Word(7177040968308302886), big.Word(828640808385465987), big.Word(4796503807648111967), big.Word(12218066339588962090), big.Word(3096046449826013543), big.Word(13228219651570631076), big.Word(5884524399280610981), big.Word(12072888130958040778)
																}
															},
															E: 65537
														},
														Version: 3,
														SerialNumber: ( * big.Int) {
															neg: false,
															abs: big.nat {
																big.Word(1)
															}
														},
														Issuer: pkix.Name {
															Country: [] string(nil),
															Organization: [] string(nil),
															OrganizationalUnit: [] string(nil),
															Locality: [] string(nil),
															Province: [] string(nil),
															StreetAddress: [] string(nil),
															PostalCode: [] string(nil),
															SerialNumber: "",
															CommonName: "apiserver-loopback-client-ca@1601561119",
															Names: [] pkix.AttributeTypeAndValue {
																pkix.AttributeTypeAndValue {
																	Type: asn1.ObjectIdentifier {
																		2,
																		5,
																		4,
																		3
																	},
																	Value: "apiserver-loopback-client-ca@1601561119"
																}
															},
															ExtraNames: [] pkix.AttributeTypeAndValue(nil)
														},
														Subject: pkix.Name {
															Country: [] string(nil),
															Organization: [] string(nil),
															OrganizationalUnit: [] string(nil),
															Locality: [] string(nil),
															Province: [] string(nil),
															StreetAddress: [] string(nil),
															PostalCode: [] string(nil),
															SerialNumber: "",
															CommonName: "apiserver-loopback-client-ca@1601561119",
															Names: [] pkix.AttributeTypeAndValue {
																pkix.AttributeTypeAndValue {
																	Type: asn1.ObjectIdentifier {
																		2,
																		5,
																		4,
																		3
																	},
																	Value: "apiserver-loopback-client-ca@1601561119"
																}
															},
															ExtraNames: [] pkix.AttributeTypeAndValue(nil)
														},
														NotBefore: time.Time {
															wall: 0,
															ext: 63737154319,
															loc: ( * time.Location)(nil)
														},
														NotAfter: time.Time {
															wall: 0,
															ext: 63768690319,
															loc: ( * time.Location)(nil)
														},
														KeyUsage: x509.KeyUsage(37),
														Extensions: [] pkix.Extension {
															pkix.Extension {
																Id: asn1.ObjectIdentifier {
																	2,
																	5,
																	29,
																	15
																},
																Critical: true,
																Value: [] uint8 {
																	3,
																	2,
																	2,
																	164
																}
															}, pkix.Extension {
																Id: asn1.ObjectIdentifier {
																	2,
																	5,
																	29,
																	19
																},
																Critical: true,
																Value: [] uint8 {
																	48,
																	3,
																	1,
																	1,
																	255
																}
															}, pkix.Extension {
																Id: asn1.ObjectIdentifier {
																	2,
																	5,
																	29,
																	14
																},
																Critical: false,
																Value: [] uint8 {
																	4,
																	20,
																	71,
																	92,
																	157,
																	228,
																	78,
																	37,
																	32,
																	202,
																	114,
																	104,
																	88,
																	149,
																	254,
																	95,
																	164,
																	58,
																	16,
																	11,
																	131,
																	67
																}
															}
														},
														ExtraExtensions: [] pkix.Extension(nil),
														UnhandledCriticalExtensions: [] asn1.ObjectIdentifier(nil),
														ExtKeyUsage: [] x509.ExtKeyUsage(nil),
														UnknownExtKeyUsage: [] asn1.ObjectIdentifier(nil),
														BasicConstraintsValid: true,
														IsCA: true,
														MaxPathLen: -1,
														MaxPathLenZero: false,
														SubjectKeyId: [] uint8 {
															71,
															92,
															157,
															228,
															78,
															37,
															32,
															202,
															114,
															104,
															88,
															149,
															254,
															95,
															164,
															58,
															16,
															11,
															131,
															67
														},
														AuthorityKeyId: [] uint8(nil),
														OCSPServer: [] string(nil),
														IssuingCertificateURL: [] string(nil),
														DNSNames: [] string(nil),
														EmailAddresses: [] string(nil),
														IPAddresses: [] net.IP(nil),
														URIs: [] * url.URL(nil),
														PermittedDNSDomainsCritical: false,
														PermittedDNSDomains: [] string(nil),
														ExcludedDNSDomains: [] string(nil),
														PermittedIPRanges: [] * net.IPNet(nil),
														ExcludedIPRanges: [] * net.IPNet(nil),
														PermittedEmailAddresses: [] string(nil),
														ExcludedEmailAddresses: [] string(nil),
														PermittedURIDomains: [] string(nil),
														ExcludedURIDomains: [] string(nil),
														CRLDistributionPoints: [] string(nil),
														PolicyIdentifiers: [] asn1.ObjectIdentifier(nil)
													}
												}
											},
											NextProtos: [] string {
												"h2",
												"http/1.1"
											},
											ServerName: "apiserver-loopback-client",
											ClientAuth: tls.ClientAuthType(0),
											ClientCAs: ( * x509.CertPool)(nil),
											InsecureSkipVerify: false,
											CipherSuites: [] uint16(nil),
											PreferServerCipherSuites: false,
											SessionTicketsDisabled: false,
											SessionTicketKey: [32] uint8 {
												0,
												0
											},
											ClientSessionCache: tls.ClientSessionCache(nil),
											MinVersion: 771,
											MaxVersion: 0,
											CurvePreferences: [] tls.CurveID(nil),
											DynamicRecordSizingDisabled: false,
											Renegotiation: tls.RenegotiationSupport(0),
											KeyLogWriter: io.Writer(nil),
											mutex: sync.RWMutex {
												w: sync.Mutex {
													state: 0,
													sema: 0
												},
												writerSem: 0,
												readerSem: 0,
												readerCount: 0,
												readerWait: 0
											},
											sessionTicketKeys: [] tls.ticketKey(nil),
											autoSessionTicketKeys: [] tls.ticketKey(nil)
										},
										TLSHandshakeTimeout: time.Duration(10000000000),
										DisableKeepAlives: false,
										DisableCompression: true,
										MaxIdleConns: 0,
										MaxIdleConnsPerHost: 25,
										MaxConnsPerHost: 0,
										IdleConnTimeout: time.Duration(90000000000),
										ResponseHeaderTimeout: time.Duration(0),
										ExpectContinueTimeout: time.Duration(0),
										TLSNextProto: map[string](func(string, * tls.Conn) http.RoundTripper) {
											"h2": (func(string, * tls.Conn) http.RoundTripper)(0x00000000009ca520)
										},
										ProxyConnectHeader: http.Header(nil),
										MaxResponseHeaderBytes: 0,
										WriteBufferSize: 0,
										ReadBufferSize: 0,
										nextProtoOnce: sync.Once {
											done: 0,
											m: sync.Mutex {
												state: 0,
												sema: 0
											}
										},
										h2transport: http.h2Transport(nil),
										tlsNextProtoWasNil: false,
										ForceAttemptHTTP2: false
									}
								}
							},
							CheckRedirect: (func( * http.Request, [] * http.Request) error)(0x0000000000000000),
							Jar: http.CookieJar(nil),
							Timeout: time.Duration(32000000000)
						}
					},
					LegacyPrefix: "/api"
				},
				lock: sync.RWMutex {
					w: sync.Mutex {
						state: 0,
						sema: 0
					},
					writerSem: 0,
					readerSem: 0,
					readerCount: 0,
					readerWait: 0
				},
				groupToServerResources: map[string] * memory.cacheEntry {},
				groupList: ( * v1.APIGroupList)(nil),
				cacheValid: false
			}
		},
		quotaConfiguration: ( * generic.simpleConfiguration) {
			evaluators: [] v1.Evaluator {
				( * core.podEvaluator) {
					listFuncByNamespace: (generic.ListFuncByNamespace)(0x0000000003359720),
					clock: clock.RealClock {}
				}, ( * core.serviceEvaluator) {
					listFuncByNamespace: (generic.ListFuncByNamespace)(0x0000000003359720)
				}, ( * core.pvcEvaluator) {
					listFuncByNamespace: (generic.ListFuncByNamespace)(0x0000000003359720)
				}, ( * generic.objectCountEvaluator) {
					groupResource: schema.GroupResource {
						Group: "",
						Resource: "configmaps"
					},
					listFuncByNamespace: (generic.ListFuncByNamespace)(0x0000000003359720),
					resourceNames: [] v1.ResourceName {
						v1.ResourceName("count/configmaps"), v1.ResourceName("configmaps")
					}
				}, ( * generic.objectCountEvaluator) {
					groupResource: schema.GroupResource {
						Group: "",
						Resource: "resourcequotas"
					},
					listFuncByNamespace: (generic.ListFuncByNamespace)(0x0000000003359720),
					resourceNames: [] v1.ResourceName {
						v1.ResourceName("count/resourcequotas"), v1.ResourceName("resourcequotas")
					}
				}, ( * generic.objectCountEvaluator) {
					groupResource: schema.GroupResource {
						Group: "",
						Resource: "replicationcontrollers"
					},
					listFuncByNamespace: (generic.ListFuncByNamespace)(0x0000000003359720),
					resourceNames: [] v1.ResourceName {
						v1.ResourceName("count/replicationcontrollers"), v1.ResourceName("replicationcontrollers")
					}
				}, ( * generic.objectCountEvaluator) {
					groupResource: schema.GroupResource {
						Group: "",
						Resource: "secrets"
					},
					listFuncByNamespace: (generic.ListFuncByNamespace)(0x0000000003359720),
					resourceNames: [] v1.ResourceName {
						v1.ResourceName("count/secrets"), v1.ResourceName("secrets")
					}
				}
			},
			ignoredResources: map[schema.GroupResource] struct {} {
				schema.GroupResource {
					Group: "",
					Resource: "bindings"
				}: {}, schema.GroupResource {
					Group: "",
					Resource: "componentstatuses"
				}: {}, schema.GroupResource {
					Group: "",
					Resource: "events"
				}: {}, schema.GroupResource {
					Group: "authentication.k8s.io",
					Resource: "tokenreviews"
				}: {}, schema.GroupResource {
					Group: "authorization.k8s.io",
					Resource: "localsubjectaccessreviews"
				}: {}, schema.GroupResource {
					Group: "authorization.k8s.io",
					Resource: "selfsubjectaccessreviews"
				}: {}, schema.GroupResource {
					Group: "authorization.k8s.io",
					Resource: "selfsubjectrulesreviews"
				}: {}, schema.GroupResource {
					Group: "authorization.k8s.io",
					Resource: "subjectaccessreviews"
				}: {}
			}
		}
	}
}
```











