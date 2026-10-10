package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsclient"
	"anime.bike/remotestorage/pkg/webfinger"
	"github.com/alecthomas/kong"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

type AuthInfo struct {
	StorageURL   string    `json:"storage_url"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
}

type AuthCache map[string]AuthInfo // remote -> auth info

var CLI struct {
	Ls       LsCmd       `cmd:"" help:"List directory contents"`
	Get      GetCmd      `cmd:"" help:"Download a file"`
	Put      PutCmd      `cmd:"" help:"Upload a file"`
	Delete   DeleteCmd   `cmd:"" help:"Delete a file"`
	Info     InfoCmd     `cmd:"" help:"Get file information"`
	Mkdir    MkdirCmd    `cmd:"" help:"Create a directory"`
	Discover DiscoverCmd `cmd:"" help:"Discover RemoteStorage for a user"`
	Login    LoginCmd    `cmd:"" help:"Authenticate with a remote"`
	Logout   LogoutCmd   `cmd:"" help:"Remove stored authentication"`
}

type LsCmd struct {
	Path  string `arg:"" help:"Remote path (e.g., user@example.com:/ or user@example.com:documents/)"`
	Long  bool   `short:"l" help:"Use long listing format"`
	All   bool   `short:"a" help:"Show hidden files (starting with .)"`
	Human bool   `short:"h" help:"Human-readable file sizes"`
}

type GetCmd struct {
	RemotePath string `arg:"" help:"Remote file path (e.g., user@example.com:document.txt)"`
	LocalPath  string `arg:"" optional:"" help:"Local file path (defaults to basename)"`
}

type PutCmd struct {
	LocalPath   string `arg:"" help:"Local file path"`
	RemotePath  string `arg:"" help:"Remote file path (e.g., user@example.com:document.txt)"`
	ContentType string `short:"c" help:"Content type (auto-detected if not specified)"`
}

type DeleteCmd struct {
	Path  string `arg:"" help:"File path to delete (e.g., user@example.com:document.txt)"`
	Force bool   `short:"f" help:"Force deletion without confirmation"`
}

type InfoCmd struct {
	Path string `arg:"" help:"File path (e.g., user@example.com:document.txt)"`
}

type MkdirCmd struct {
	Path string `arg:"" help:"Directory path to create (e.g., user@example.com:newfolder/)"`
}

type DiscoverCmd struct {
	UserAddress string `arg:"" help:"User address (e.g., user@example.com)"`
	Raw         bool   `short:"r" help:"Output raw JSON response from discovery endpoint"`
}

type LoginCmd struct {
	Remote string `arg:"" help:"Remote to authenticate (e.g., user@example.com)"`
}

type LogoutCmd struct {
	Remote string `arg:"" help:"Remote to logout from (e.g., user@example.com)"`
}

func main() {
	// Create context that can be cancelled
	appCtx := context.Background()

	ctx := kong.Parse(&CLI,
		kong.Name("rscli"),
		kong.Description("RemoteStorage command-line client"),
		kong.UsageOnError(),
		kong.BindTo(appCtx, (*context.Context)(nil)),
	)

	err := ctx.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// parseRemotePath splits a path like "user@example.com:path/to/file" into remote and path
func parseRemotePath(remotePath string) (remote, path string, err error) {
	parts := strings.SplitN(remotePath, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid path format, expected remote:path (e.g., user@example.com:documents/)")
	}

	remote = parts[0]
	path = parts[1]

	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return remote, path, nil
}

// getConfigDir returns the config directory path
func getConfigDir() (string, error) {
	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		configDir = filepath.Join(home, ".config")
	}
	return filepath.Join(configDir, "rscli"), nil
}

// loadAuthCache loads the authentication cache from disk
func loadAuthCache() (AuthCache, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return nil, err
	}

	authFile := filepath.Join(configDir, "auth.json")
	data, err := os.ReadFile(authFile)
	if err != nil {
		if os.IsNotExist(err) {
			return make(AuthCache), nil
		}
		return nil, err
	}

	var cache AuthCache
	err = json.Unmarshal(data, &cache)
	if err != nil {
		return nil, err
	}

	return cache, nil
}

// saveAuthCache saves the authentication cache to disk
func saveAuthCache(cache AuthCache) error {
	configDir, err := getConfigDir()
	if err != nil {
		return err
	}

	// Create config directory if it doesn't exist
	err = os.MkdirAll(configDir, 0700)
	if err != nil {
		return err
	}

	authFile := filepath.Join(configDir, "auth.json")
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(authFile, data, 0600)
}

// getOrCreateAuth gets existing auth or creates new auth for a remote
func getOrCreateAuth(ctx context.Context, remote string) (*AuthInfo, error) {
	cache, err := loadAuthCache()
	if err != nil {
		return nil, err
	}

	// Check if we have valid auth
	if auth, ok := cache[remote]; ok {
		// Check if token is still valid
		if auth.ExpiresAt.IsZero() || auth.ExpiresAt.After(time.Now()) {
			return &auth, nil
		}
	}

	// Need to authenticate
	fmt.Printf("Authentication required for %s\n", remote)
	fmt.Printf("Performing RemoteStorage discovery...\n")

	// Perform discovery
	storageInfo, err := rsclient.Discover(ctx, remote, nil)
	if err != nil {
		return nil, fmt.Errorf("discovery failed: %w", err)
	}

	fmt.Printf("Discovery successful! Storage URL: %s\n", storageInfo.Href)

	// Build OAuth URL
	// For 5apps.com and similar servers, client_id must match redirect_uri domain
	// Always use HTTP for the IPv4 loopback redirect URI.
	redirectURI := "http://127.0.0.1:8765/"
	clientID := os.Getenv("RSCLI_CLIENT_ID")
	if clientID == "" {
		clientID = redirectURI
	}
	scope := "*:rw"

	var token string
	var expiresAt time.Time
	if authzURL, tokenURL, ok := rsclient.GetPKCEEndpoints(storageInfo); ok {
		// Spec §10.1: clients SHOULD use PKCE when it is advertised.
		fmt.Printf("Using authorization code flow with PKCE (token endpoint: %s)\n", tokenURL)
		tok, err := pkceLogin(ctx, authzURL, tokenURL, clientID, redirectURI, scope)
		if err != nil {
			return nil, err
		}
		token = tok.AccessToken
		expiresAt = tok.Expiry
	} else {
		tok, err := implicitLogin(ctx, storageInfo, clientID, redirectURI, scope)
		if err != nil {
			return nil, err
		}
		token = tok
	}

	// Save auth info
	auth := AuthInfo{
		StorageURL:  storageInfo.Href,
		AccessToken: token,
		ExpiresAt:   expiresAt,
	}

	if cache == nil {
		cache = make(AuthCache)
	}
	cache[remote] = auth

	err = saveAuthCache(cache)
	if err != nil {
		return nil, fmt.Errorf("failed to save auth: %w", err)
	}

	fmt.Printf("Successfully authenticated with %s\n", remote)
	return &auth, nil
}

// openAuthURL prints the authorization URL and tries to open it in a browser.
func openAuthURL(oauthURL string) {
	fmt.Printf("\n=== Authentication Required ===\n")
	fmt.Printf("Opening browser for authentication...\n")
	fmt.Printf("\nVisit this URL to authenticate:\n%s\n\n", oauthURL)

	if err := browser.OpenURL(oauthURL); err != nil {
		fmt.Printf("Failed to open browser automatically: %v\n", err)
		fmt.Printf("Please open the URL manually in your browser.\n")
	}
}

// pkceLogin runs the authorization code flow with PKCE (spec §10.1).
func pkceLogin(ctx context.Context, authzURL, tokenURL, clientID, redirectURI, scope string) (*oauth2.Token, error) {
	scopes, err := rsclient.ParseScope(scope)
	if err != nil {
		return nil, err
	}
	config := rsclient.GetPKCEOAuth2Config(authzURL, tokenURL, clientID, redirectURI, scopes)
	verifier := oauth2.GenerateVerifier()
	state := oauth2.GenerateVerifier()

	type result struct {
		code string
		err  error
	}
	resultChan := make(chan result, 1)
	listener, err := net.Listen("tcp", "127.0.0.1:8765")
	if err != nil {
		return nil, fmt.Errorf("start OAuth callback listener: %w", err)
	}

	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			setOAuthCallbackHeaders(w, false)
			if !isOAuthCallbackHost(r.Host) {
				http.Error(w, "Invalid callback host", http.StatusBadRequest)
				return
			}
			if r.Method != http.MethodGet || r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			q := r.URL.Query()
			var res result
			if q.Get("state") != state {
				http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
				return
			}
			switch {
			case q.Get("error") != "":
				res.err = fmt.Errorf("OAuth authorization failed")
			case q.Get("code") == "":
				http.Error(w, "Missing authorization code", http.StatusBadRequest)
				return
			default:
				res.code = q.Get("code")
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			if res.err != nil {
				w.Write([]byte("<h1>Authentication Failed</h1><p>Please return to the terminal.</p>"))
			} else {
				w.Write([]byte("<h1>Authentication Successful!</h1><p>You can close this window and return to the terminal.</p>"))
			}
			select {
			case resultChan <- res:
			default:
			}
		}),
	}
	go func() {
		if err := server.Serve(listener); err != http.ErrServerClosed {
			select {
			case resultChan <- result{err: err}:
			default:
			}
		}
	}()
	defer server.Close()

	openAuthURL(rsclient.GetPKCEAuthURL(config, state, verifier))

	var res result
	select {
	case res = <-resultChan:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("authentication timeout")
	}
	if res.err != nil {
		return nil, res.err
	}

	tok, err := rsclient.ExchangePKCECode(ctx, config, res.code, verifier)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	return tok, nil
}

// implicitLogin runs the implicit grant flow.
func implicitLogin(ctx context.Context, storageInfo *rs.StorageInfo, clientID, redirectURI, scope string) (string, error) {
	authURL, err := rsclient.GetAuthURL(storageInfo)
	if err != nil {
		return "", fmt.Errorf("no auth endpoint found: %w", err)
	}
	parsedAuthURL, err := url.Parse(authURL)
	if err != nil {
		return "", fmt.Errorf("invalid auth endpoint: %w", err)
	}
	state := oauth2.GenerateVerifier()
	query := parsedAuthURL.Query()
	query.Set("client_id", clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "token")
	query.Set("scope", scope)
	query.Set("state", state)
	parsedAuthURL.RawQuery = query.Encode()
	oauthURL := parsedAuthURL.String()

	resultChan := make(chan implicitCallbackResult, 1)
	listener, err := net.Listen("tcp", "127.0.0.1:8765")
	if err != nil {
		return "", fmt.Errorf("start OAuth callback listener: %w", err)
	}
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		Handler:           implicitCallbackHandler(state, resultChan),
	}
	go func() {
		if err := server.Serve(listener); err != http.ErrServerClosed {
			select {
			case resultChan <- implicitCallbackResult{err: err}:
			default:
			}
		}
	}()
	defer server.Close()

	openAuthURL(oauthURL)
	select {
	case result := <-resultChan:
		return result.token, result.err
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(5 * time.Minute):
		return "", fmt.Errorf("authentication timeout")
	}
}

type implicitCallbackResult struct {
	token string
	err   error
}

func isOAuthCallbackHost(host string) bool {
	return strings.EqualFold(host, "localhost:8765") || host == "127.0.0.1:8765"
}

func setOAuthCallbackHeaders(w http.ResponseWriter, implicit bool) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	if implicit {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
	} else {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	}
}

func implicitCallbackHandler(state string, resultChan chan<- implicitCallbackResult) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setOAuthCallbackHeaders(w, true)
		if !isOAuthCallbackHost(r.Host) {
			http.Error(w, "Invalid callback host", http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/" {
			if r.Method != http.MethodGet || r.URL.RawQuery != "" {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, `<!doctype html><title>RemoteStorage authentication</title><h1 id="title">Processing</h1><p id="status">Return to the terminal when complete.</p><script>
const p=new URLSearchParams(location.hash.slice(1)), b=new URLSearchParams();
history.replaceState(null,'','/');
b.set('state',p.get('state')||''); b.set('access_token',p.get('access_token')||''); b.set('error',p.get('error')||'');
fetch('/callback',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b.toString()}).then(r=>{document.getElementById('title').textContent=r.ok?'Authentication complete':'Authentication failed'}).catch(()=>{document.getElementById('title').textContent='Authentication failed'});
</script>`)
			return
		}
		if r.URL.Path != "/callback" || r.Method != http.MethodPost || r.URL.RawQuery != "" {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			http.Error(w, "Unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid callback", http.StatusBadRequest)
			return
		}
		if r.Form.Get("state") != state {
			http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
			return
		}
		result := implicitCallbackResult{}
		if r.Form.Get("error") != "" {
			result.err = fmt.Errorf("OAuth authorization failed")
		} else if r.Form.Get("access_token") == "" {
			http.Error(w, "Missing access token", http.StatusBadRequest)
			return
		} else {
			result.token = r.Form.Get("access_token")
		}
		select {
		case resultChan <- result:
		default:
		}
		w.WriteHeader(http.StatusOK)
	})
}

// getClient creates a client for the given remote
func getClient(ctx context.Context, remote string) (*rsclient.Client, error) {
	auth, err := getOrCreateAuth(ctx, remote)
	if err != nil {
		return nil, err
	}

	return rsclient.NewWithToken(auth.StorageURL, auth.AccessToken), nil
}

func (cmd *LsCmd) Run(ctx context.Context) error {
	remote, path, err := parseRemotePath(cmd.Path)
	if err != nil {
		return err
	}

	client, err := getClient(ctx, remote)
	if err != nil {
		return err
	}

	listing, err := client.ListDirectory(path)
	if err != nil {
		return err
	}

	// Filter and collect item names
	var names []string
	filteredItems := make(map[string]rs.FolderItem)
	for name, item := range listing.Items {
		// Skip hidden files unless -a is specified
		if !cmd.All && strings.HasPrefix(name, ".") {
			continue
		}
		names = append(names, name)
		filteredItems[name] = item
	}

	// Sort names (directories first, then files, both alphabetically)
	sort.Slice(names, func(i, j int) bool {
		iIsDir := strings.HasSuffix(names[i], "/")
		jIsDir := strings.HasSuffix(names[j], "/")

		if iIsDir != jIsDir {
			return iIsDir // directories come first
		}
		return names[i] < names[j] // alphabetical within same type
	})

	if cmd.Long {
		// Long format
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TYPE\tSIZE\tMODIFIED\tETAG\tNAME")

		for _, name := range names {
			item := filteredItems[name]
			itemType := "file"
			if strings.HasSuffix(name, "/") {
				itemType = "dir"
			}

			size := formatSize(item.ContentLength, cmd.Human)
			etag := item.ETag
			if len(etag) > 16 {
				etag = etag[:16] + "..."
			}

			// Parse and format modification time
			modified := "-"
			if item.LastModified != "" {
				if t, err := time.Parse(time.RFC1123, item.LastModified); err == nil {
					modified = t.Format("Jan 02 15:04")
				}
			}

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				itemType,
				size,
				modified,
				etag,
				name,
			)
		}
		w.Flush()
	} else {
		// Simple format
		for _, name := range names {
			fmt.Println(name)
		}
	}

	return nil
}

func (cmd *GetCmd) Run(ctx context.Context) error {
	remote, path, err := parseRemotePath(cmd.RemotePath)
	if err != nil {
		return err
	}

	client, err := getClient(ctx, remote)
	if err != nil {
		return err
	}

	localPath := cmd.LocalPath
	if localPath == "" {
		localPath = filepath.Base(path)
	}

	fmt.Printf("Downloading %s to %s...\n", cmd.RemotePath, localPath)
	err = client.DownloadFile(path, localPath)
	if err != nil {
		return err
	}

	fmt.Println("Download complete")
	return nil
}

func (cmd *PutCmd) Run(ctx context.Context) error {
	remote, remotePath, err := parseRemotePath(cmd.RemotePath)
	if err != nil {
		return err
	}

	// Prevent writing to bare root path
	if remotePath == "/" || remotePath == "" {
		return fmt.Errorf("cannot write to root path '/'; use a module path like 'user@example.com:documents/file.txt'")
	}

	// For directories, append the filename
	if strings.HasSuffix(remotePath, "/") {
		remotePath = remotePath + filepath.Base(cmd.LocalPath)
	}

	client, err := getClient(ctx, remote)
	if err != nil {
		return err
	}

	fmt.Printf("Uploading %s to %s%s...\n", cmd.LocalPath, remote, remotePath)
	etag, err := client.UploadFile(cmd.LocalPath, remotePath, cmd.ContentType)
	if err != nil {
		return err
	}

	fmt.Printf("Upload complete (ETag: %s)\n", etag)
	return nil
}

func (cmd *DeleteCmd) Run(ctx context.Context) error {
	remote, path, err := parseRemotePath(cmd.Path)
	if err != nil {
		return err
	}

	// Prevent deleting from bare root path
	if path == "/" || path == "" {
		return fmt.Errorf("cannot delete from root path '/'; use a module path like 'user@example.com:documents/file.txt'")
	}

	client, err := getClient(ctx, remote)
	if err != nil {
		return err
	}

	if !cmd.Force {
		fmt.Printf("Delete %s? [y/N] ", cmd.Path)
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Cancelled")
			return nil
		}
	}

	err = client.DeleteFile(path, "")
	if err != nil {
		return err
	}

	fmt.Printf("Deleted %s\n", cmd.Path)
	return nil
}

func (cmd *InfoCmd) Run(ctx context.Context) error {
	remote, path, err := parseRemotePath(cmd.Path)
	if err != nil {
		return err
	}

	client, err := getClient(ctx, remote)
	if err != nil {
		return err
	}

	info, err := client.GetFileInfo(path)
	if err != nil {
		return err
	}

	fmt.Printf("Path: %s\n", info.Path)
	fmt.Printf("Name: %s\n", info.Name)
	fmt.Printf("Type: %s\n", info.ContentType)
	fmt.Printf("Size: %s\n", formatSize(info.Size, true))
	fmt.Printf("ETag: %s\n", info.ETag)
	if !info.LastModified.IsZero() {
		fmt.Printf("Modified: %s\n", info.LastModified.Format(time.RFC3339))
	}

	return nil
}

func (cmd *MkdirCmd) Run(ctx context.Context) error {
	remote, path, err := parseRemotePath(cmd.Path)
	if err != nil {
		return err
	}

	// Prevent mkdir on bare root path
	if path == "/" || path == "" {
		return fmt.Errorf("cannot create directory at root path '/'; use a module path like 'user@example.com:documents/'")
	}

	client, err := getClient(ctx, remote)
	if err != nil {
		return err
	}

	// Ensure path ends with /
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	// Create an empty file to create the directory
	// RemoteStorage creates directories implicitly
	placeholderPath := path + ".remotestorage"
	resp, err := client.Put(placeholderPath, strings.NewReader(""), "text/plain", "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		fmt.Printf("Created directory %s\n", cmd.Path)
		return nil
	}

	return fmt.Errorf("failed to create directory: server returned %d", resp.StatusCode)
}

func (cmd *DiscoverCmd) Run(ctx context.Context) error {
	// Always get raw discovery response first
	rawResponse, err := rsclient.DiscoverRaw(ctx, cmd.UserAddress, nil)
	if err != nil {
		return err
	}

	if cmd.Raw {
		// Parse to validate and format JSON
		var data json.RawMessage
		if err := json.Unmarshal(rawResponse, &data); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}

		// Output formatted JSON
		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		fmt.Println(string(jsonData))
		return nil
	}

	// Parse the raw response to get StorageInfo
	// Extract host to build discovery URL
	resource := webfinger.NormalizeResource(cmd.UserAddress)
	host, err := webfinger.ExtractHost(resource)
	if err != nil {
		return fmt.Errorf("failed to extract host: %w", err)
	}
	discoveryURL := webfinger.BuildURL(host, resource)

	storageInfo, err := rsclient.ParseDiscoveryResponse([]byte(rawResponse), discoveryURL)
	if err != nil {
		return err
	}

	fmt.Printf("Discovery URL: %s\n", storageInfo.DiscoveryURL)
	fmt.Printf("Storage URL: %s\n", storageInfo.Href)
	fmt.Printf("Relation: %s\n", storageInfo.Rel)

	if storageInfo.Properties != nil {
		fmt.Println("\nProperties:")

		// Known properties with explanations
		propertyExplanations := map[string]string{
			"http://remotestorage.io/spec/version":           "Protocol version supported by the server",
			"http://tools.ietf.org/html/rfc6749#section-4.2": "OAuth 2.0 authorization endpoint URL",
			"http://tools.ietf.org/html/rfc7233":             "HTTP range requests support",
			"http://remotestorage.io/spec/web-authoring":     "WebDAV-like authoring support",
			"http://tools.ietf.org/html/rfc6750#section-2.3": "OAuth 2.0 bearer token via query (deprecated)",
			"auth-endpoint": "Alternative OAuth authorization endpoint",
		}

		for key, value := range storageInfo.Properties {
			// Format value, converting nil to null
			var formattedValue string
			if value == nil {
				formattedValue = "null"
			} else {
				formattedValue = fmt.Sprintf("%v", value)
			}

			fmt.Printf("  %s: %s\n", key, formattedValue)

			// Add explanation if known
			if explanation, ok := propertyExplanations[key]; ok {
				fmt.Printf("    → %s\n", explanation)
			}
		}
	}

	// Try to get auth URL
	authURL, err := rsclient.GetAuthURL(storageInfo)
	if err == nil {
		fmt.Printf("\nAuth URL: %s\n", authURL)
	}

	return nil
}

func (cmd *LoginCmd) Run(ctx context.Context) error {
	_, err := getOrCreateAuth(ctx, cmd.Remote)
	return err
}

func (cmd *LogoutCmd) Run(ctx context.Context) error {
	cache, err := loadAuthCache()
	if err != nil {
		return err
	}

	if _, ok := cache[cmd.Remote]; !ok {
		return fmt.Errorf("not authenticated with %s", cmd.Remote)
	}

	delete(cache, cmd.Remote)

	err = saveAuthCache(cache)
	if err != nil {
		return err
	}

	fmt.Printf("Logged out from %s\n", cmd.Remote)
	return nil
}

func formatSize(bytes int64, human bool) string {
	if !human {
		return fmt.Sprintf("%d", bytes)
	}

	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
