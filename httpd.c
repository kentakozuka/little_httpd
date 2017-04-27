/*
    httpd.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>

/***********************************
 * ライブラリ
 ***********************************/
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#define _GNU_SOURCE
#include <getopt.h>

/***********************************
 * 定数
 ***********************************/
//サーバ名
#define SERVER_NAME "LittleHTTP"
//サーババージョン
#define SERVER_VERSION "1.0"
#define HTTP_MINOR_VERSION 0
#define BLOCK_BUF_SIZE 1024
#define LINE_BUF_SIZE 4096
//リクエストボディの最大長
#define MAX_REQUEST_BODY_LENGTH (1024 * 1024)
#define MAX_BACKLOG 5
//デフォルトポート
#define DEFAULT_PORT "80"
//引数エラーメッセージ
#define USAGE "Usage: %s [--port=n] [--chroot --user=u --group=g] [--debug] <docroot>\n"


/***********************************
 * 構造体
 ***********************************/
//httpヘッダ
struct HTTPHeaderField {
	char *name;
	char *value;
	struct HTTPHeaderField *next;
};

//httpリクエスト
struct HTTPRequest {
	int protocol_minor_version;
	char *method;
	char *path;
	struct HTTPHeaderField *header;
	char *body;
	long length;
};
//ファイル情報
struct FileInfo {
	char *path;
	long size;
	int ok;
};

/***********************************
 * 関数プロトタイプ
 ***********************************/
static void setup_environment(char *root, char *user, char *group);
typedef void (*sighandler_t)(int);
static void install_signal_handlers(void);
static void trap_signal(int sig, sighandler_t handler);
static void signal_exit(int sig);
static void wait_child(int sig);
static void become_daemon(void);
static int listen_socket(char *port);
static void server_main(int server, char *docroot);
static void service(FILE *in, FILE *out, char *docroot);
static struct HTTPRequest* read_request(FILE *in);
static void read_request_line(struct HTTPRequest *req, FILE *in);
static struct HTTPHeaderField* read_header_field(FILE *in);
static void upcase(char *str);
static void free_request(struct HTTPRequest *req);
static long content_length(struct HTTPRequest *req);
static char* lookup_header_field_value(struct HTTPRequest *req, char *name);
static void respond_to(struct HTTPRequest *req, FILE *out, char *docroot);
static void do_file_response(struct HTTPRequest *req, FILE *out, char *docroot);
static void method_not_allowed(struct HTTPRequest *req, FILE *out);
static void not_implemented(struct HTTPRequest *req, FILE *out);
static void not_found(struct HTTPRequest *req, FILE *out);
static void output_common_header_fields(struct HTTPRequest *req, FILE *out, char *status);
static struct FileInfo* get_fileinfo(char *docroot, char *path);
static char* build_fspath(char *docroot, char *path);
static void free_fileinfo(struct FileInfo *info);
static char* guess_content_type(struct FileInfo *info);
static void* xmalloc(size_t sz);
static void log_exit(const char *fmt, ...);


//デバッグフラグ
static int debug_mode = 0;

/*
 * プログラムの環境変数を格納する構造体
 * getopt_longで使用するため、各要素を配列として格納する
 * 	{
 * 		//マッチさせる長いオプション
 * 		const char *name,
 * 		//引数を持つかどうか
 * 		int has_arg,
 * 		//判定結果の格納先
 * 		int *flag,
 * 		//判定結果として返す値
 * 		int val
 * 	};
 */
static struct option longopts[] = {
	{"debug",	no_argument,		&debug_mode,	1},
	{"chroot",	no_argument,		NULL,			'c'},
	{"user",	required_argument,	NULL,			'u'},
	{"group",	required_argument,	NULL,			'g'},
	{"port",	required_argument,	NULL,			'p'},
	{"help",	no_argument,		NULL,			'h'},
	{0,			0,					0,				0}
};

/*
 * main
 * @param 引数の総個数
 * @param 引数の文字列を指すポインタの配列
 */
int
main(int argc, char *argv[])
{
	int server;
	char *port = NULL;
	//ドキュメントルート
	char *docroot;
	//chrootフラグ
	int do_chroot = 0;
	//ユーザ
	char *user = NULL;
	//グループ
	char *group = NULL;
	//オプション
	int opt;

	//プログラムの環境変数の設定
	//getopt_log()でループさせて、プログラム環境変数に値を入れる
	while ((opt = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
		switch (opt) {
			case 0:
				break;
			case 'c':
				do_chroot = 1;
				break;
			case 'u':
				user = optarg;
				break;
			case 'g':
				group = optarg;
				break;
			case 'p':
				port = optarg;
				break;
			case 'h':
				fprintf(stdout, USAGE, argv[0]);
				exit(0);
				case '?':
				fprintf(stderr, USAGE, argv[0]);
				exit(1);
		}
	}
	//引数が足りない場合
	//getoptはoptindに「次に処理すべき引数のインデクスを格納している
	//ここではoptindを使用してオプションの値ではない値を処理する
    if (optind != argc - 1) {
		//使用方法を出力
		fprintf(stderr, USAGE, argv[0]);
		//終了
		exit(1);
	}
	//引数をドキュメントルートに設定
	docroot = argv[optind];

	if (do_chroot) {
		setup_environment(docroot, user, group);
		docroot = "";
	}
	//シグナルハンドラを登録
	install_signal_handlers();

 	//socket(), build(), listen()を担当する
	server = listen_socket(port);

	//デバッグモードでない場合
	if (!debug_mode) {
		openlog(SERVER_NAME, LOG_PID|LOG_NDELAY, LOG_DAEMON);
		become_daemon();
	}

	server_main(server, docroot);
	exit(0);
}

/*
 * chroot()すると同時にクレデンシャルをuserとgroupに変更する関数
 *
 * スーパユーザで/etcが必要な関数呼び出し
 * スーパユーザでchroot()を実行
 * 別のクレデンシャルに変更
 *
 * @param *root
 * @param *user
 * @param *group
 */
static void
setup_environment(char *root, char *user, char *group)
{
	struct passwd *pw;
	struct group *gr;
	
	//nullチェック
	if (!user || !group) {
		fprintf(stderr, "use both of --user and --group\n");
		exit(1);
	}
	//グループ情報をグループ名から検索する
	gr = getgrnam(group);
	if (!gr) {
		fprintf(stderr, "no such group: %s\n", group);
		exit(1);
	}
	//自分の実グループIDと実行グループIDを変更する
	if (setgid(gr->gr_gid) < 0) {
		perror("setgid(2)");
		exit(1);
	}
	// /etc/groupなどのデータベースを見て、
	// ユーザの補足グループを自プロセスに設定する（グループも同様）
	if (initgroups(user, gr->gr_gid) < 0) {
		perror("initgroups(2)");
		exit(1);
	}
	//ユーザ情報をユーザ名から検索する
	pw = getpwnam(user);
	if (!pw) {
		fprintf(stderr, "no such user: %s\n", user);
		exit(1);
	}
	//chroot()する:自分のルートディレクトリをrootに設定する
	chroot(root);
	//自分の実ユーザIDと実行ユーザIDを変更する
	if (setuid(pw->pw_uid) < 0) {
		perror("setuid(2)");
		exit(1);
	}
}

/*
 * 各シグナルのハンドラを設定するメソッド
 */
static void
become_daemon(void)
{
	int n;

	//ルートディレクトリに移動
	if (chdir("/") < 0) {
		log_exit("chdir(2) failed: %s", strerror(errno));
	}
	//標準入出力を/dev/nullにつなぐ
	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);
	//フォークし、端末に従属している親のプロセスを終了する
	n = fork();
	if (n < 0) log_exit("fork(2) failed: %s", strerror(errno));
	if (n != 0) _exit(0);
	/*
	 * setsid()
	 * 新しいセッションを作成し、自分がセッションリーダになる
	 * 同時に、そのセッションで最初のプロセスグループを作成し、そのグループリーダになる
	 * @return 成功：セッションID、失敗：-1
	 */
	if (setsid() < 0) log_exit("setsid(2) failed: %s", strerror(errno));
}

/*
 * 各シグナルのハンドラを設定するメソッド
 */
static void
install_signal_handlers(void)
{
	//プロセス終了時
    trap_signal(SIGTERM, signal_exit);
	//子プロセスが停止または終了時
    trap_signal(SIGCHLD, wait_child);
}

/*
 * シグナルを補足するメソッド
 * @param シグナル
 * @param シグナルハンドラ(シグナルを処理するメソッド)
 */
static void
trap_signal(int sig, sighandler_t handler)
{
	struct sigaction act;
	//シグナルハンドラをsigactionに設定
	act.sa_handler = handler;
	//sa_maskを空にする
	sigemptyset(&act.sa_mask);
	//システムコールの再起動を設定
	act.sa_flags = SA_RESTART;
	/*
	 * sigaction()
	 * @param
	 * @param シグナルハンドラの関数ポインタ
	 * @param
	 */
	if (sigaction(sig, &act, NULL) < 0) {
		//エラーログを吐いて終了
		log_exit("sigaction() failed: %s", strerror(errno));
	}
}

/*
 * プロセス終了時に呼ばれるシグナルハンドラメソッド
 * @param シグナル
 */
static void
signal_exit(int sig)
{
    log_exit("exit by signal %d", sig);
}

static void
wait_child(int sig)
{
    wait(NULL);
}

/*
 * socket(), build(), listen()を担当する
 */
static int 
listen_socket(char *port)
{
	//取得したいアドレスの情報
    struct addrinfo hints;
	//レスポンス
	struct addrinfo *res;
	//?
	struct addrinfo *ai;
    int err;

	// buf の先頭から n バイト分 ch をセットします
    memset(&hints, 0, sizeof(struct addrinfo));
	//IPv4のみ使用する
    hints.ai_family		= AF_INET;
	//TCPを使用する
    hints.ai_socktype	= SOCK_STREAM;
	//ソケットをサーバ用に使用する
    hints.ai_flags		= AI_PASSIVE;

	/*
	 * 名前解決
	 *
	 * int getaddrinfo(
	 * 		const char *node,
	 * 		const char *service,
     * 		const struct addrinfo *hints,
     * 		struct addrinfo **res);
	 *
     * getaddrinfo() は、node と service を渡すと、
	 * 一つ以上の addrinfo 構造体を返す。
	 * それぞれの addrinfo 構造体には、 
	 * bind(2) や connect(2) を呼び出す際に指定できるインターネットアドレスが格納されている。
	 *
     * hints 引数
	 * 		addrinfo 構造体を指し示し、この構造体を用いて 
	 * 		res が指すリストに入れて返すソケットアドレス構造体を選択するための基準を指定する。
	 * 		hints が NULL でない場合、 hints は addrinfo 構造体を指し示し、
	 * 		その構造体のフィールド ai_family, ai_socktype, ai_protocol で
	 * 		getaddrinfo() が返すソケットアドレス集合に対する基準を指定する。
	 *
	 * struct addrinfo {
	 * 		int              ai_flags;
	 * 		int              ai_family;
	 * 		int              ai_socktype;
	 * 		int              ai_protocol;
	 * 		socklen_t        ai_addrlen;
	 * 		struct sockaddr *ai_addr;
	 * 		char            *ai_canonname;
	 * 		struct addrinfo *ai_next;
	 * };
	 *
	 * ai_family
	 * 		返されるアドレスの希望のアドレスファミリーを指定する。
	 * 		指定できる有効な値としては AF_INET と AF_INET6 がある。
	 * 		AF_UNSPEC を指定すると、 getaddrinfo() は node と service で使用できるいずれかの
	 * 		アドレスファミリー (例えば IPv4 か IPv6) の ソケットアドレスを返すことを求められる。
	 * ai_socktype
	 * 		このフィールドは推奨のソケット型 (例えば SOCK_STREAM や SOCK_DGRAM) を指定する。
	 * 		このフィールドに 0 を指定すると、任意のソケット型のソケットアドレスを getaddrinfo() が返してよいことを意味する。
	 * ai_protocol
	 * 		返されるソケットアドレスのプロトコルを指定する。
	 * 		0 を指定すると、任意のプロトコルののソケットアドレスを getaddrinfo() が返してよいことを意味する。
	 * ai_flags
	 * 		追加のオプション (下記) を指定する。
	 * 		複数のフラグを指定する際には、それらのビット単位の OR をとって指定する。
	 */

	//エラーの場合
    if ((err = getaddrinfo(NULL, port, &hints, &res)) != 0)
        log_exit(gai_strerror(err));
	//アドレス情報が複数帰ってきた場合のため、ループさせる
	//（ただし、このプログラムではIPv4を指定しているためループはしない）
	//戻り値のリンクリストを回す
    for (ai = res; ai; ai = ai->ai_next) {
        int sock;

		//ソケットを作成しファイルディスクリプタを返す
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		//作成失敗ならスキップ
        if (sock < 0) continue;
		//接続を待つアドレスをソケットに割り当てる
		//成功? 0 : -1
        if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
            close(sock);
            continue;
        }
		//ソケットが待受用であることをカーネルに知らせる
        if (listen(sock, MAX_BACKLOG) < 0) {
            close(sock);
            continue;
        }
		//addrfinfoはmallocで割り当てられているため使用後に開放する
        freeaddrinfo(res);
		//ソケットを返す
		//このプログラムでは１つでも成功したら即正常終了する
        return sock;
    }
	//失敗した場合
    log_exit("failed to listen socket");
    return -1;  
}

/*
 * サーバのメイン処理
 * ソケットを待ち受けにして接続があった場合はプロセスをフォークする
 * その後の処理はservice()で行う
 */
static void
server_main(int server, char *docroot)
{
    for (;;) {
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof addr;
        int sock;
        int pid;

		/*ソケットにクライアントが接続してくるのを待つ
		 * 接続が完了したら接続済ストリームのファイルディスクリプタを返す
		 * 
		 * 引数
		 * 	socket		ソケット記述子
		 * 	address		呼び出し側のクライアントのアドレスポインタ
		 * 	address_len	アドレス構造体の長さ
		 * 
		 * 戻り値
		 * 	新しいソケットファイルディスクリプタ 	成功(保留中のクライアント接続がある場合)
		 * 	-1 	失敗
		 * 
		 * 戻り値が失敗(-1)の場合のerrnoの値：
		 * EWOULDBLOCK 	O_NUNBLOCKが指定されていて保留中の接続が無い場合に発生する。
		 */
        sock = accept(server, (struct sockaddr*)&addr, &addrlen);
		//エラーの場合
        if (sock < 0) log_exit("accept(2) failed: %s", strerror(errno));
		//成功の場合
		//子プロセスを作成
        pid = fork();
		//失敗の場合
        if (pid < 0) exit(3);
		/* 子プロセス */
        if (pid == 0) {
            FILE *inf = fdopen(sock, "r");
            FILE *outf = fdopen(sock, "w");

			//serviceにhttpの処理を投げる
            service(inf, outf, docroot);
			//たぶんこれいらない
            exit(0);
		/* 親プロセス */
        } else {
			//ソケットをクローズ
        	close(sock);
		}
    }
}

/*
 * httpの処理メソッド
 * httpのリクエストを処理してレスポンスを返すメソッド
 */
static void
service(FILE *in, FILE *out, char *docroot)
{
    struct HTTPRequest *req;

	//リクエストを処理
    req = read_request(in);
	//レスポンスを処理
    respond_to(req, out, docroot);
	//リクエストを開放
    free_request(req);
}
/*
 * リクエスト処理メソッド
 * ストリームからリクエストを読んでstruct httprequestを作成する
 */
static struct HTTPRequest*
read_request(FILE *in)
{
	struct HTTPRequest *req;
	struct HTTPHeaderField *h;

	//HTTPRequestのメモリ領域を確保
	req = xmalloc(sizeof(struct HTTPRequest));
	//リクエストライン解析
	read_request_line(req, in);
	req->header = NULL;
	//リクエストヘッダ解析
	while (h = read_header_field(in)) {
		h->next = req->header;
		req->header = h;
	}
	//エンティティボディ読み込み
	req->length = content_length(req);
	if (req->length != 0) {
	if (req->length > MAX_REQUEST_BODY_LENGTH)
		log_exit("request body too long");
		req->body = xmalloc(req->length);
	if (fread(req->body, req->length, 1, in) < 1)
		log_exit("failed to read request body");
	} else {
		req->body = NULL;
	}
	return req;
}

/*
 * リクエストライン解析メソッド
 */
static void
read_request_line(struct HTTPRequest *req, FILE *in)
{
	char buf[LINE_BUF_SIZE];
	char *path, *p;

	//１行読み込む
	//エラーの場合
	if (!fgets(buf, LINE_BUF_SIZE, in))
		log_exit("no request line");
	/* httpのメソッドを読み込む */
	//第一引数の文字列の中で最初に現れた第二引数のポインタを返します。
	p = strchr(buf, ' ');
	if (!p) log_exit("parse error on request line (1): %s", buf);
	//現在位置している場所に'\0'を代入してからポインタを１すすめる
	*p++ = '\0';
	req->method = xmalloc(p - buf);
	strcpy(req->method, buf);
	upcase(req->method);

	/* パスを読み込む */
	path = p;
	//第一引数の文字列の中で最初に現れた第二引数のポインタを返します。
	p = strchr(path, ' ');
	if (!p) log_exit("parse error on request line (2): %s", buf);
	//現在位置している場所に'\0'を代入してからポインタを１すすめる
	*p++ = '\0';
	req->path = xmalloc(p - path);
	strcpy(req->path, path);

	/* HTTPのバージョンを確認する */
	//バージョンが１でなければエラー終了
	if (strncasecmp(p, "HTTP/1.", strlen("HTTP/1.")) != 0)
		log_exit("parse error on request line (3): %s", buf);
	p += strlen("HTTP/1.");
	req->protocol_minor_version = atoi(p);
}

/*
 * ヘッダー読み込みメソッド
 */
static struct HTTPHeaderField*
read_header_field(FILE *in)
{
	struct HTTPHeaderField *h;
	char buf[LINE_BUF_SIZE];
	char *p;

	//１行読み込む
	if (!fgets(buf, LINE_BUF_SIZE, in)) {
		log_exit("failed to read request header field: %s", strerror(errno));
	}
	//空行チェック
	//httpでは基本的に/r/nだが、端末からテストすると/nになってしまうため両方対応
	if ((buf[0] == '\n') || (strcmp(buf, "\r\n") == 0)) {
		return NULL;
	}

	p = strchr(buf, ':');
	if (!p) log_exit("parse error on request header field: %s", buf);
	*p++ = '\0';
	h = xmalloc(sizeof(struct HTTPHeaderField));
	h->name = xmalloc(p - buf);
	strcpy(h->name, buf);

	p += strspn(p, " \t"); 
	h->value = xmalloc(strlen(p) + 1);
	strcpy(h->value, p);

	return h;
}

/*
 * Upper Case変換メソッド
 * @param *str	文字列のポインタ
 */
static void
upcase(char *str)
{
	char *p;
	for (p = str; *p; p++) {
		*p = (char)toupper((int)*p);
	}
}

/*
 * リクエスト構造体開放メソッド
 */
static void
free_request(struct HTTPRequest *req)
{
	struct HTTPHeaderField *h, *head;

	head = req->header;
	while (head) {
		h = head;
		head = head->next;
		free(h->name);
		free(h->value);
		free(h);
	}
	free(req->method);
	free(req->path);
	free(req->body);
	free(req);
}

/*
 * struct HTTPRequestからリクエスのエンティティボディの長さを得る
 */
static long
content_length(struct HTTPRequest *req)
{
	char *val;
	long len;
    
	val = lookup_header_field_value(req, "Content-Length");
	if (!val) return 0;
	len = atol(val);
	if (len < 0) log_exit("negative Content-Length value");
	return len;
}

/*
 * ヘッダフィールドを名前検索するメソッド
 */
static char*
lookup_header_field_value(struct HTTPRequest *req, char *name)
{
	struct HTTPHeaderField *h;

	//ヘッダ文ループ
	for (h = req->header; h; h = h->next) {
		//文字列を比較する ? 同じ -> 0 : 異なる -> 0以外
	if (strcasecmp(h->name, name) == 0)
		return h->value;
	}
	//ヘッダが存在しない場合
	return NULL;
}

/*
 * リクエストreqに対するレスポンスをoutに書き込みます
 */
static void
respond_to(struct HTTPRequest *req, FILE *out, char *docroot)
{
	if (strcmp(req->method, "GET") == 0)
		do_file_response(req, out, docroot);
	else if (strcmp(req->method, "HEAD") == 0)
		do_file_response(req, out, docroot);
	else if (strcmp(req->method, "POST") == 0)
		method_not_allowed(req, out);
	else
		not_implemented(req, out);
}

/*
 * getリクエストを出力する
 * @param *req		httpリクエスト情報
 * @param *out		リクエストhttp文出力先
 * @param *docroot	ドキュメントルート
 */
static void
do_file_response(struct HTTPRequest *req, FILE *out, char *docroot)
{
	struct FileInfo *info;

	//ファイル情報を取得して構造体に格納
	info = get_fileinfo(docroot, req->path);
	if (!info->ok) {
		free_fileinfo(info);
		not_found(req, out);
		return;
	}
	//共通ヘッダ部分を書き出し
	output_common_header_fields(req, out, "200 OK");
	fprintf(out, "Content-Length: %ld\r\n", info->size);
	fprintf(out, "Content-Type: %s\r\n", guess_content_type(info));
	fprintf(out, "\r\n");
	/*
	 * ボディを作成
	 */
	if (strcmp(req->method, "HEAD") != 0) {
		int fd;
		char buf[BLOCK_BUF_SIZE];
		ssize_t n;

		//リクエスト対象のファイルを開く
		fd = open(info->path, O_RDONLY);
		if (fd < 0)
		log_exit("failed to open %s: %s", info->path, strerror(errno));
		//1行ずつ読み込んで書き出す
		for (;;) {
			n = read(fd, buf, BLOCK_BUF_SIZE);
			if (n < 0)
			log_exit("failed to read %s: %s", info->path, strerror(errno));
			if (n == 0)
			break;
			if (fwrite(buf, 1, n, out) < n)
			log_exit("failed to write to socket");
		}
		//終わったら閉じる
		close(fd);
	}
	//解放
	fflush(out);
	free_fileinfo(info);
}

/*
 * 405エラーを返す場合のヘッダ部分の書き出し関数
 * @param *req		httpリクエスト情報
 * @param *out		リクエストhttp文出力先
 */
static void
method_not_allowed(struct HTTPRequest *req, FILE *out)
{
	output_common_header_fields(req, out, "405 Method Not Allowed");
	fprintf(out, "Content-Type: text/html\r\n");
	fprintf(out, "\r\n");
	fprintf(out, "<html>\r\n");
	fprintf(out, "<header>\r\n");
	fprintf(out, "<title>405 Method Not Allowed</title>\r\n");
	fprintf(out, "<header>\r\n");
	fprintf(out, "<body>\r\n");
	fprintf(out, "<p>The request method %s is not allowed</p>\r\n", req->method);
	fprintf(out, "</body>\r\n");
	fprintf(out, "</html>\r\n");
	fflush(out);
}

/*
 * 501エラーを返す場合のヘッダ部分の書き出し関数
 * @param *req		httpリクエスト情報
 * @param *out		リクエストhttp文出力先
 */
static void
not_implemented(struct HTTPRequest *req, FILE *out)
{
	output_common_header_fields(req, out, "501 Not Implemented");
	fprintf(out, "Content-Type: text/html\r\n");
	fprintf(out, "\r\n");
	fprintf(out, "<html>\r\n");
	fprintf(out, "<header>\r\n");
	fprintf(out, "<title>501 Not Implemented</title>\r\n");
	fprintf(out, "<header>\r\n");
	fprintf(out, "<body>\r\n");
	fprintf(out, "<p>The request method %s is not implemented</p>\r\n", req->method);
	fprintf(out, "</body>\r\n");
	fprintf(out, "</html>\r\n");
	fflush(out);
}

/*
 * 404エラーを返す場合のヘッダ部分の書き出し関数
 * @param *req		httpリクエスト情報
 * @param *out		リクエストhttp文出力先
 */
static void
not_found(struct HTTPRequest *req, FILE *out)
{
	output_common_header_fields(req, out, "404 Not Found");
	fprintf(out, "Content-Type: text/html\r\n");
	fprintf(out, "\r\n");
	if (strcmp(req->method, "HEAD") != 0) {
		fprintf(out, "<html>\r\n");
		fprintf(out, "<header><title>Not Found</title><header>\r\n");
		fprintf(out, "<body><p>File not found</p></body>\r\n");
		fprintf(out, "</html>\r\n");
	}
	fflush(out);
}

#define TIME_BUF_SIZE 64

/*
 * 正常時の場合のヘッダ部分の書き出し関数
 * @param *req		httpリクエスト情報
 * @param *out		リクエストhttp文出力先
 */
static void
output_common_header_fields(struct HTTPRequest *req, FILE *out, char *status)
{
	time_t t;
	struct tm *tm;
	char buf[TIME_BUF_SIZE];

	t = time(NULL);
	tm = gmtime(&t);
	if (!tm) log_exit("gmtime() failed: %s", strerror(errno));
	strftime(buf, TIME_BUF_SIZE, "%a, %d %b %Y %H:%M:%S GMT", tm);
	fprintf(out, "HTTP/1.%d %s\r\n", HTTP_MINOR_VERSION, status);
	fprintf(out, "Date: %s\r\n", buf);
	fprintf(out, "Server: %s/%s\r\n", SERVER_NAME, SERVER_VERSION);
	fprintf(out, "Connection: close\r\n");
}

/*
 * リクエストで指定されたファイルの情報を取得する関数
 * struct FileInfo作成する
 * @param 	*docroot		ドキュメントルート
 * @param 	*urlpath		ドキュメントルートからの相対パス
 * @return	*FileInfo		ファイル情報の構造体
 */
static struct FileInfo*
get_fileinfo(char *docroot, char *urlpath)
{
	struct FileInfo *info;
	struct stat st;

	info = xmalloc(sizeof(struct FileInfo));
	info->path = build_fspath(docroot, urlpath);
	info->ok = 0;
	if (lstat(info->path, &st) < 0) return info;
	if (!S_ISREG(st.st_mode)) return info;
	info->ok = 1;
	info->size = st.st_size;
	return info;
}

/*
 * ファイル絶対パス作成メソッド
 * ドキュメントルートとファイル相対パスをつなげて絶対パスを作成します
 */
static char *
build_fspath(char *docroot, char *urlpath)
{
	char *path;

	path = xmalloc(strlen(docroot) + 1 + strlen(urlpath) + 1);
	sprintf(path, "%s/%s", docroot, urlpath);
	return path;
}

/*
 * struct FileInfoメモリ解放メソッド
 */
static void
free_fileinfo(struct FileInfo *info)
{
	free(info->path);
	free(info);
}

/*
 * ファイルタイプ判別メソッド
 * TODO: 現在はそのままtext/plainを返す -> 治したい
 */
static char*
guess_content_type(struct FileInfo *info)
{
	return "text/plain";
}

/*
 * メモリ割当メソッド
 * @param 割当サイズ
 * @return 汎用ポインタ（なんのポインタにでもなれる）
 */
static void*
xmalloc(size_t sz)
{
	void *p;
	//メモリ割当
	p = malloc(sz);
	//失敗：nullの場合はログ出力して終了
	if (!p) log_exit("failed to allocate memory");
	//汎用ポインタを返す
	return p;
}

/*
 * エラー終了メソッド
 * エラーログを出力し、プログラムを終了する
 * @param char エラー文（可変長引数）
 */
static void
log_exit(const char *fmt, ...)
{
	//可変長引数の方va_listで変数を宣言
	va_list ap;

	//可変長引数の使用開始
	va_start(ap, fmt);
	//デバッグ中（debug_mode == 1)のときは標準出力
	if (debug_mode) {
		vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);
	}
	//デバッグ中出ない場合はvsyslogに丸投げ
	else {
		vsyslog(LOG_ERR, fmt, ap);
	}
	//可変長引数の使用終了
	va_end(ap);
	//ステータス１（エラー）を渡して終了
	exit(1);
}
