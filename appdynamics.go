package appdynamics

//#cgo CFLAGS: -I${SRCDIR}/sdk_lib
//#cgo LDFLAGS: -L${SRCDIR}/sdk_lib/lib -lappdynamics -ldl -Wl,-rpath,${SRCDIR}/sdk_lib/lib
//#cgo linux LDFLAGS: -lrt
//#include "appdynamics.h"
//#include <stdlib.h>
//#include <stdint.h>
/*
extern void appd_config_set_golang(void);

uintptr_t bthandle_to_uint(appd_bt_handle bthandle) {
    return (uintptr_t) bthandle;
}
appd_bt_handle uint_to_bthandle(uintptr_t bthandle) {
    return (appd_bt_handle) bthandle;
}

uintptr_t echandle_to_uint(appd_exitcall_handle echandle) {
    return (uintptr_t) echandle;
}
appd_exitcall_handle uint_to_echandle(uintptr_t echandle) {
    return (appd_exitcall_handle) echandle;
}
*/
import "C"

import (
    "errors"
    "fmt"
    "os"
    "unsafe"
)

// The required name of the correlation header.
//
// Other AppDynamics agents perform automatic correlation for certain
// types of entry and exit points by looking for a correlation header
// in the payload with this name.
//
// Upstream Correlation
// ====================
//
// When your SDK instrumented process receives a continuing transaction
// from an upstream agent that supports automatic correlation, extract
// the header named APPD_CORRELATION_HEADER_NAME from the incoming
// payload and pass it to StartBT():
//
//   string hdr = req.Header.Get(APPD_CORRELATION_HEADER_NAME);
//   BtHandle bt = StartBT("fraud detection", hdr);
//
// If the header retrieved by the req.Header.Get() function is
// valid, the BT started on the second line will be a continuation of the
// business transaction started by the upstream service.
//
// Downstream Correlation
// ======================
//
// If you are making an exit call where a downstream agent supports
// automatic correlation, inject a header named APPD_CORREATION_HEADER_NAME
// into the outgoing payload. The value of the header is retrieved using the
// GetExitcallCorrelationHeader() function:
//
//   ExitcallHandle inventory = StartExitcall(bt, "inventory");
//   string hdr = GetExitcallCorrelationHeader(inventory);
//   client := &http.Client{}
//   req, err := http.NewRequest("POST", "https://inventory/holds/sku123123")
//   req.Header.Add(APPD_CORRELATION_HEADER_NAME, hdr)
//   resp, err := client.Do(req)
//
// In this example, the http functions (import "net/http") are used
// to make an HTTP POST request with an HTTP header containing the correlation
// header as retrieved by GetExitcallCorrelationHeader(). The header
// is given the name APPD_CORRELATION_HEADER_NAME. A downstream agent that
// supports automatic correlation for HTTP entry points will automatically
// extract the correlation header and perform distributed transaction tracing.
const APPD_CORRELATION_HEADER_NAME string = "singularityheader"

type ExitcallHandle uint64
type BtHandle uint64

type Config struct {
    AppName, TierName, NodeName string

    Controller Controller
    Logging LoggingConfig

    /*
     * Set to true if you want the SDK to check for configuration in the
     * environment on init. Note that because this happens on init, the
     * environment settings override whatever configuration you set in
     * your program.
     *
     * See the documentation for appd_config_getenv in the C/C++ SDK
     * for more information.
     */
    UseConfigFromEnv bool

    /*
     * If UseConfigFromEnv is set, this specifies the prefix to use for
     * environment variable names. If UseConfigFromEnv is true and this
     * is empty, then the default (APPD) is used.
     *
     * See the documentation for appd_config_getenv in the C/C++ SDK
     * for more information.
     */
    EnvVarPrefix string

    /*
     * appd_sdk_init relies on controller configuration to start business
     * transactions. This is an asynchronous action so that InitSDK does
     * not block your program. This Config field allows you to instruct
     * InitSDK to wait for up to InitTimeoutMs milliseconds and
     * wait until it has received controller configuration and is ready to
     * capture BTs.
     *
     * X  : Wait up to X milliseconds for controller configuration.
     * 0  : Do not wait for controller configuration.
     * -1 : Wait indefinitely until controller configuration is received by agent
     */
    InitTimeoutMs int
}

type Controller struct {
    Host                            string
    Port                            uint16
    Account, AccessKey              string
    UseSSL                          bool
    CertificateFile, CertificateDir string

    HTTPProxy HTTPProxy
}

type HTTPProxy struct {
    Host                   string
    Port                   uint16
    Username, PasswordFile string
}

type LogLevel int

const (
    APPD_LOG_LEVEL_DEFAULT LogLevel = iota
    APPD_LOG_LEVEL_TRACE
    APPD_LOG_LEVEL_DEBUG
    APPD_LOG_LEVEL_INFO
    APPD_LOG_LEVEL_WARN
    APPD_LOG_LEVEL_ERROR
    APPD_LOG_LEVEL_FATAL
)

type LoggingConfig struct {
    BaseDir             string
    MinimumLevel        LogLevel
    MaxNumFiles         uint
    MaxFileSizeBytes    uint
}

/**
 * Configuration of an application context (tenant) for the SDK.
 */
type ContextConfig struct {
    AppName  string
    TierName string
    NodeName string
}

// Error levels for passing to AddBTError() and
// AddExitcallError().
type ErrorLevel int

const (
    APPD_LEVEL_NOTICE ErrorLevel = iota
    APPD_LEVEL_WARNING
    APPD_LEVEL_ERROR
)

// Valid backend types to pass to AddBackend()
const (
    APPD_BACKEND_HTTP       = "HTTP"
    APPD_BACKEND_DB         = "DB"
    APPD_BACKEND_CACHE      = "CACHE"
    APPD_BACKEND_RABBITMQ   = "RABBITMQ"
    APPD_BACKEND_WEBSERVICE = "WEBSERVICE"
    APPD_BACKEND_JMS        = "JMS"
)

// Converts the Golang Config struct to the C appd_config struct equivalent
func marshalConfig(from *Config) C.struct_appd_config {
    to := C.struct_appd_config{}
    C.appd_config_init(&to)

    to.app_name = C.CString(from.AppName)
    to.tier_name = C.CString(from.TierName)
    to.node_name = C.CString(from.NodeName)

    to.controller.host = C.CString(from.Controller.Host)
    to.controller.port = C.ushort(from.Controller.Port)
    to.controller.account = C.CString(from.Controller.Account)
    to.controller.access_key = C.CString(from.Controller.AccessKey)
    if from.Controller.UseSSL {
        to.controller.use_ssl = C.char(1)
    } else {
        to.controller.use_ssl = C.char(0)
    }

    if len(from.Controller.CertificateDir) != 0 {
        to.controller.certificate_dir = C.CString(from.Controller.CertificateDir)
    }

    if len(from.Controller.CertificateFile) != 0 {
        to.controller.certificate_file = C.CString(from.Controller.CertificateFile)
    } else if from.Controller.UseSSL {
        ps := string(os.PathSeparator)
        certFilePath := os.Getenv("GOPATH") + ps + "src" + ps + "appdynamics" +
            ps + "ca-bundle.crt"
        if file, err := os.Open(certFilePath); err == nil {
            file.Close()
            to.controller.certificate_file = C.CString(certFilePath)
        }
    }

    if len(from.Controller.HTTPProxy.Host) != 0 {
        to.controller.http_proxy.host = C.CString(from.Controller.HTTPProxy.Host)
    }
    to.controller.http_proxy.port = C.ushort(from.Controller.HTTPProxy.Port)
    to.controller.http_proxy.username = C.CString(from.Controller.HTTPProxy.Username)
    to.controller.http_proxy.password_file = C.CString(from.Controller.HTTPProxy.PasswordFile)

    switch from.Logging.MinimumLevel {
    case APPD_LOG_LEVEL_DEBUG:
        to.logging.min_level = C.APPD_LOG_LEVEL_DEBUG
    case APPD_LOG_LEVEL_TRACE:
        to.logging.min_level = C.APPD_LOG_LEVEL_TRACE
    case APPD_LOG_LEVEL_INFO:
        to.logging.min_level = C.APPD_LOG_LEVEL_INFO
    case APPD_LOG_LEVEL_WARN:
        to.logging.min_level = C.APPD_LOG_LEVEL_WARN
    case APPD_LOG_LEVEL_ERROR:
        to.logging.min_level = C.APPD_LOG_LEVEL_ERROR
    case APPD_LOG_LEVEL_FATAL:
        to.logging.min_level = C.APPD_LOG_LEVEL_FATAL
    }

    if len(from.Logging.BaseDir) != 0 {
        to.logging.log_dir = C.CString(from.Logging.BaseDir)
    }

    if from.Logging.MaxNumFiles != 0 {
        to.logging.max_num_files = C.uint(from.Logging.MaxNumFiles)
    }

    if from.Logging.MaxFileSizeBytes != 0 {
        to.logging.max_file_size_bytes = C.uint(from.Logging.MaxFileSizeBytes)
    }

    to.init_timeout_ms = C.int(from.InitTimeoutMs)

    return to
}

// Frees the C strings that were allocated in marshalConfig().
// The strings allocated in marshalConfig() are not garbage collected.
func freeConfigMembers(cfg C.struct_appd_config) {
    if cfg.app_name != nil {
        C.free(unsafe.Pointer(cfg.app_name))
    }
    if cfg.tier_name != nil {
        C.free(unsafe.Pointer(cfg.tier_name))
    }
    if cfg.node_name != nil {
        C.free(unsafe.Pointer(cfg.node_name))
    }
    if cfg.controller.host != nil {
        C.free(unsafe.Pointer(cfg.controller.host))
    }
    if cfg.controller.account != nil {
        C.free(unsafe.Pointer(cfg.controller.account))
    }
    if cfg.controller.access_key != nil {
        C.free(unsafe.Pointer(cfg.controller.access_key))
    }
    if cfg.controller.certificate_file != nil {
        C.free(unsafe.Pointer(cfg.controller.certificate_file))
    }
    if cfg.controller.certificate_dir != nil {
        C.free(unsafe.Pointer(cfg.controller.certificate_dir))
    }
    if cfg.controller.http_proxy.host != nil {
        C.free(unsafe.Pointer(cfg.controller.http_proxy.host))
    }
    if cfg.controller.http_proxy.username != nil {
        C.free(unsafe.Pointer(cfg.controller.http_proxy.username))
    }
    if cfg.controller.http_proxy.password_file != nil {
        C.free(unsafe.Pointer(cfg.controller.http_proxy.password_file))
    }
}

// Converts the Golang ContextConfig struct to the C appd_context_config struct equivalent
func marshalContextConfig(from *ContextConfig) C.struct_appd_context_config {
    to := C.struct_appd_context_config{}

    to.app_name = C.CString(from.AppName)
    to.tier_name = C.CString(from.TierName)
    to.node_name = C.CString(from.NodeName)

    return to
}

func freeContextConfigMembers(cfg C.struct_appd_context_config) {
    if cfg.app_name != nil {
        C.free(unsafe.Pointer(cfg.app_name))
    }
    if cfg.tier_name != nil {
        C.free(unsafe.Pointer(cfg.tier_name))
    }
    if cfg.node_name != nil {
        C.free(unsafe.Pointer(cfg.node_name))
    }
}

// Add application context to AppDynamics configuration for multi-tenancy.
func AddAppContextToConfig(cfg *Config, context string, contextCfg *ContextConfig) error {
    cs := C.CString(context)
    defer C.free(unsafe.Pointer(cs))

    c_contextCfg := marshalContextConfig(contextCfg)
    defer freeContextConfigMembers(c_contextCfg)

    result := int(C.appd_config_add_app_context(nil, cs, &c_contextCfg))
    if result != 0 {
        return errors.New("Could not add app context to config.")
    }

    return nil
}

// Initializes the AppDynamics SDK.
// Returns an error on failure.
func InitSDK(cfg *Config) error {
    // convert the go struct to a c struct
    C.appd_config_set_golang()
    c_cfg := marshalConfig(cfg)
    defer freeConfigMembers(c_cfg)

    if cfg.UseConfigFromEnv {
        if cfg.EnvVarPrefix != "" {
            csPrefix := C.CString(cfg.EnvVarPrefix)
            defer C.free(unsafe.Pointer(csPrefix))
            C.appd_config_getenv(&c_cfg, csPrefix)
        } else {
            C.appd_config_getenv(&c_cfg, nil)
        }
    }

    result := int(C.appd_sdk_init(&c_cfg))

    if result != 0 {
        return errors.New("Could not initialize the Golang SDK.")
    }

    return nil
}

// Adds a backend with the given name, type, and identifying properties.
// Returns an error on failure.
//
// The resolve parameter:
//   Normally, if an agent picks up a correlation header for an unresolved
//   backend, it will resolve itself as that backend. This is usually the
//   desired behavior.
//
//   However, if the backend is actually an uninstrumented tier that is
//   passing through the correlation header (for example, a message queue
//   or proxy), then you may wish the backend to show up distinct from the
//   tier that it routes to. If you set resolve to false, correlation headers
//   generated for exit calls to this backend in the SDK will instruct
//   downstream agents to report as distinct from the backend.
//
//   For example: if you have Tier A talking to uninstrumented Backend B
//   which routes to instrumented Tier C, if you set resolve to true,
//   the flow map will be A -> C. If you set resolve to false, the flow
//   map will be A -> B -> C.
func AddBackend(name, backendType string, identifyingProperties map[string]string, resolve bool) error {
    ns := C.CString(name)
    defer C.free(unsafe.Pointer(ns))
    ts := C.CString(backendType)
    defer C.free(unsafe.Pointer(ts))

    // Step 1/4: declare the backend
    C.appd_backend_declare(ts, ns)

    // Step 2/4: add identifying properties
    for key, value := range identifyingProperties {
        ks := C.CString(key)
        vs := C.CString(value)

        result_cint := C.appd_backend_set_identifying_property(ns, ks, vs)
        result := int(result_cint)

        C.free(unsafe.Pointer(ks))
        C.free(unsafe.Pointer(vs))

        if result != 0 {
            return fmt.Errorf("Could not add identifying property (key: %sm value: %s) for backend %s. See SDK log for more info.",
                key, value, name)
        }
    }

    // Step 3/4: prevent agent resolution if desired
    if !resolve {
        result_cint := C.appd_backend_prevent_agent_resolution(ns)
        if int(result_cint) != 0 {
            return fmt.Errorf("Could not prevent agent resolution on backend %s. See SDK log for more info.", name)
        }
    }

    // Step 4/4: add the backend
    result_cint := C.appd_backend_add(ns)
    if int(result_cint) != 0 {
        return fmt.Errorf("Could not add backend %s. See SDK log for more info.", name)
    }

    return nil
}

// Starts a business transaction.
// Returns an opaque handle for the business transaction that was started
func StartBT(name, correlation_header string) BtHandle {
    ns := C.CString(name)
    defer C.free(unsafe.Pointer(ns))
    chs := C.CString(correlation_header)
    defer C.free(unsafe.Pointer(chs))

    return BtHandle(C.bthandle_to_uint(C.appd_bt_begin(ns, chs)))
}

func StartBTWithAppContext(context, name, correlation_header string) BtHandle {
    cs := C.CString(context)
    defer C.free(unsafe.Pointer(cs))
    ns := C.CString(name)
    defer C.free(unsafe.Pointer(ns))
    chs := C.CString(correlation_header)
    defer C.free(unsafe.Pointer(chs))

    return BtHandle(C.bthandle_to_uint(C.appd_bt_begin_with_app_context(cs, ns, chs)))
}

//
// Store a BT handle for retrieval with appd_bt_get.
//
// This function allows you to store a BT in a global registry to retrieve
// later. This is convenient when you need to start and end a BT in
// separate places, and it is difficult to pass the handle to the BT
// through the parts of the code that need it.
//
// When the BT is ended, the handle is removed from the global registry.
//
// Example
// =======
//
//     func BeginTransaction(txid uint64, sku uint64, price float32) {
//         bt := appd.StartBT("payment-processing", "")
//         appd.StoreBT(bt, strconv.FormatUint(txid, 10))
//         // ...
//     }
//
// @param bt
//     The BT to store.
// @param guid
//     A globally unique identifier to associate with the given BT.

func StoreBT(bt BtHandle, guid string) {
    gs := C.CString(guid)
    defer C.free(unsafe.Pointer(gs))
    bth := C.uint_to_bthandle(C.uintptr_t(bt))

    C.appd_bt_store(bth, gs)
}

// // Get a BT handle associated with the given guid by StoreBT.
func GetBT(guid string) BtHandle {
    gs := C.CString(guid)
    defer C.free(unsafe.Pointer(gs))

    return BtHandle(C.bthandle_to_uint(C.appd_bt_get(gs)))
}

// translates the Go "enum" to the C equivalent in appdynamics.h
func GetCErrorLevel(level ErrorLevel) C.enum_appd_error_level {
    switch level {
    case APPD_LEVEL_NOTICE:
        return C.APPD_LEVEL_NOTICE
    case APPD_LEVEL_WARNING:
        return C.APPD_LEVEL_WARNING
    case APPD_LEVEL_ERROR:
        return C.APPD_LEVEL_ERROR
    }
    return C.APPD_LEVEL_ERROR
}

// Add an error to a business transaction.
//
// Errors are reported as part of the business transaction. However, you can
// add an error without marking the business transaction as an error (e.g.,
// for non-fatal errors).
func AddBTError(
    bt BtHandle,
    level ErrorLevel,
    message string,
    mark_bt_as_error bool) {

    ms := C.CString(message)
    defer C.free(unsafe.Pointer(ms))

    var mark_bt_as_error_int int
    if mark_bt_as_error {
        mark_bt_as_error_int = 1
    } else {
        mark_bt_as_error_int = 0
    }

    C.appd_bt_add_error(
        C.uint_to_bthandle(C.uintptr_t(bt)),
        GetCErrorLevel(level),
        ms,
        C.int(mark_bt_as_error_int))
}

// Returns true if the business transaction is taking a snapshot,
// otherwise false.
func IsBTSnapshotting(bt BtHandle) bool {
    bth := C.uint_to_bthandle(C.uintptr_t(bt))
    result := int8(C.appd_bt_is_snapshotting(bth))
    return result != 0
}

// Add user data to a snapshot (if one is being taken).
//
// User data is added to a snapshot if one is occurring. Data should be UTF-8.
//
// It is safe to call this function when a snapshot is not occurring.
// When the given business transcation is NOT snapshotting, this function
// immediately returns. However, if extracting the data to pass to this
// function is expensive, you can use IsBTSnapshotting() to check
// if the business transaction is snapshotting before extracting the data
// and calling this function.
func AddUserDataToBT(bt BtHandle, key, value string) {
    ks := C.CString(key)
    defer C.free(unsafe.Pointer(ks))
    vs := C.CString(value)
    defer C.free(unsafe.Pointer(vs))
    bth := C.uint_to_bthandle(C.uintptr_t(bt))

    C.appd_bt_add_user_data(bth, ks, vs)
}

// Set URL for a snapshot (if one is being taken).
//
// URL is set for a snapshot if one is occurring. Data should be UTF-8.
//
// It is safe to call this function when a snapshot is not occurring.
// When the given business transcation is NOT snapshotting, this function
// immediately returns. However, if extracting the data to pass to this
// function is expensive, you can use IsBTSnapshotting() to check
// if the business transaction is snapshotting before extracting the data
// and calling this function.
func SetBTURL(bt BtHandle, url string) {
    us := C.CString(url)
    defer C.free(unsafe.Pointer(us))
    bth := C.uint_to_bthandle(C.uintptr_t(bt))

    C.appd_bt_set_url(bth, us)
}

// End the given business transaction.
func EndBT(bt BtHandle) {
    bth := C.uint_to_bthandle(C.uintptr_t(bt))
    C.appd_bt_end(bth)
}

// Start an exit call as part of a business transaction.
//
// Returns An opaque handle to the exit call that was started.
func StartExitcall(bt BtHandle, backend string) ExitcallHandle {
    bs := C.CString(backend)
    defer C.free(unsafe.Pointer(bs))
    bth := C.uint_to_bthandle(C.uintptr_t(bt))
    return ExitcallHandle(C.echandle_to_uint(C.appd_exitcall_begin(bth, bs)))
}

// Store an exit call handle for retrieval with appd_exitcall_get.
//
//  This function allows you to store an exit call in a global registry to
//  retrieve later. This is convenient when you need to start and end the
//  call in separate places, and it is difficult to pass the handle through
//  the parts of the code that need it.
//
//  The handle is removed when the exit call (or the BT containing it) ends.
func StoreExitcall(exitcall ExitcallHandle, guid string) {
    gs := C.CString(guid)
    defer C.free(unsafe.Pointer(gs))
    ech := C.uint_to_echandle(C.uintptr_t(exitcall))

    C.appd_exitcall_store(ech, gs)
}

// // Get an exit call associated with a guid via StoreExitcall.
func GetExitcall(guid string) ExitcallHandle {
    gs := C.CString(guid)
    defer C.free(unsafe.Pointer(gs))

    return ExitcallHandle(C.echandle_to_uint(C.appd_exitcall_get(gs)))
}

// Set the details string for an exit call.
//
// This can be used, for example, to add the SQL statement that a DB backend
// has executed as part of the exit call.
// Returns an error on failure.
func SetExitcallDetails(exitcall ExitcallHandle, details string) error {
    ds := C.CString(details)
    defer C.free(unsafe.Pointer(ds))
    ech := C.uint_to_echandle(C.uintptr_t(exitcall))

    result := int(C.appd_exitcall_set_details(ech, ds))
    if result != 0 {
        return errors.New("Could not set exitcall details")
    }

    return nil
}

// Get the header for correlating a business transaction.
//
// If a business transaction makes exit calls that you wish to correlate
// across, you should retrieve the correlation header and inject it into
// your exit call's payload.
//
// The C string that is returned from the C.appd_get_exitcall_get_correlation_header()
// is freed when the exit call ends. Do not free it yourself.
//
// Returns a 7-bit ASCII string containing the correlation information.
//     You can inject this into your payload for an exit call. An
//     agent on the other end can then extract the header from your
//     payload and continue the business transaction. On error, a
//     message is logged and the default header that prevents
//     downstream bt detection is returned.
func GetExitcallCorrelationHeader(exitcall ExitcallHandle) string {
    ech := C.uint_to_echandle(C.uintptr_t(exitcall))
    header := C.appd_exitcall_get_correlation_header(ech)
    return C.GoString(header)
}

// Add an error to the exit call.
func AddExitcallError(
    exitcall ExitcallHandle,
    level ErrorLevel,
    message string,
    mark_bt_as_error bool) {

    ms := C.CString(message)
    defer C.free(unsafe.Pointer(ms))

    var mark_bt_as_error_int int
    if mark_bt_as_error {
        mark_bt_as_error_int = 1
    } else {
        mark_bt_as_error_int = 0
    }

    C.appd_exitcall_add_error(
        C.uint_to_echandle(C.uintptr_t(exitcall)),
        GetCErrorLevel(level),
        ms,
        C.int(mark_bt_as_error_int))
}

// Complete the exit call.
func EndExitcall(exitcall ExitcallHandle) {
    C.appd_exitcall_end(C.uint_to_echandle(C.uintptr_t(exitcall)))
}

func TerminateSDK() {
    C.appd_sdk_term()
}
