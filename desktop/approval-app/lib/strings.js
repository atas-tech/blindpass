// SPDX-License-Identifier: AGPL-3.0-only
// English and Vietnamese strings for the approval app. Wording follows the
// console's approvals namespace (packages/i18n/locales/*/console.json) so a
// decision reads the same in both surfaces. Values are plain text: the views
// render them with Text.PlainText and never as rich text.
.pragma library

var LOCALES = ["en", "vi"];

var en = {
  "app.title": "BlindPass approvals",
  "app.surface": "Approvals",
  "app.metadataOnly": "This app reads request metadata only. It never receives secret values.",
  "language.label": "Language",

  "signIn.title": "Sign in to decide approvals",
  "signIn.body": "Your access token stays in this app's memory. A refresh token is kept in your runtime directory, readable only by your user account, until you sign out.",
  "signIn.controller": "Controller",
  "signIn.controllerHint": "The https:// address of your BlindPass controller. http:// is accepted only for this machine.",
  "signIn.username": "Username",
  "signIn.password": "Password",
  "signIn.usernameRequired": "Enter your username.",
  "signIn.passwordRequired": "Enter your password.",
  "signIn.submit": "Sign in",
  "signIn.working": "Signing in…",
  "signIn.invalid": "The username or password is wrong.",
  "signIn.changePassword": "Your password is temporary. Change it in the console, then sign in here.",
  "signIn.signedOut": "You signed out. The session was ended on the controller.",
  "signIn.signedOutLocal": "You signed out here, but the controller couldn't be told. The session ends on its own within 20 minutes of the last refresh.",
  "signIn.expired": "Your session ended on the controller. Sign in again.",
  "signIn.otherController": "A stored session belonged to a different controller. It was deleted without being sent anywhere.",
  "signIn.storeFailed": "Signed in, but the refresh token couldn't be stored. You'll need to sign in again after restarting the app.",

  "url.empty": "Enter the controller address.",
  "url.invalid": "That isn't a valid address.",
  "url.scheme": "Use https://. http:// is accepted only for 127.0.0.1, localhost or [::1].",
  "url.credentials": "Remove the user name or password from the address.",
  "url.path": "Enter only the scheme, host and port, with no path.",

  "trust.verified": "Certificate and host name verified with your system trust store",
  "trust.loopback": "Local controller over http, on this machine only",
  "session.signedInAs": "Signed in as {user}",
  "session.signOut": "Sign out",
  "session.lock": "Lock",

  "errors.tls": "The controller's certificate couldn't be verified for this address, so the connection was closed before anything was sent.",
  "errors.network": "The controller couldn't be reached.",
  "errors.timeout": "The controller didn't answer in time.",
  "errors.redirect": "The controller answered with a redirect. This app doesn't follow redirects, so nothing more was sent. Use the controller's direct address.",
  "errors.scheme": "This address uses a scheme the app doesn't allow.",
  "errors.noFleet": "This controller doesn't serve fleet approvals.",
  "errors.rateLimited": "Too many attempts. Wait a moment and try again.",
  "errors.unavailable": "The controller couldn't complete the request. Try again shortly.",
  "errors.forbidden": "Your role doesn't allow deciding approvals.",
  "errors.offline": "Can't reach the controller. Showing what was last loaded; decisions are paused.",

  "queue.title": "Waiting for you",
  "queue.count.one": "{count} pending",
  "queue.count.other": "{count} pending",
  "queue.empty": "Nothing is waiting for you.",
  "queue.emptyBody": "New requests appear here within 15 seconds while this window is open.",
  "queue.updated": "Updated {time}",
  "queue.refresh": "Refresh",
  "queue.loading": "Loading approvals…",
  "queue.more": "More approvals are waiting than this list shows. Decide these first, or use the console.",

  "kind.exchange": "Secret exchange",
  "kind.operation": "Fleet operation",
  "status.pending": "Pending",
  "status.approved": "Approved",
  "status.rejected": "Rejected",
  "status.expired": "Expired",
  "mode.file": "file",
  "mode.socket": "socket",

  "row.exchange": "{requester} asks for {secret}",
  "row.operation": "{action} for {unit}",
  "row.closes": "Closes in {time}",
  "row.operations.one": "{count} operation",
  "row.operations.other": "{count} operations",

  "detail.back": "Back to the list",
  "detail.recipient": "Recipient",
  "detail.scope": "Scope",
  "detail.purpose": "Purpose, as written by the requester",
  "detail.noPurpose": "No purpose given.",
  "detail.requester": "Requested by",
  "detail.node": "Node",
  "detail.workload": "Workload",
  "detail.account": "Account",
  "detail.rule": "Policy rule",
  "detail.approvers": "Approvers",
  "detail.members": "Operations in this approval",
  "detail.member": "{resource} · invocation {invocation} · by {requester}",
  "detail.closes": "Decision window closes in",
  "detail.closed": "The decision window has closed.",
  "detail.clockUnknown": "Closes at {time} controller time",
  "detail.requested": "Requested",
  "detail.approve": "Approve…",
  "detail.reject": "Reject…",
  "detail.notFound": "This approval isn't available any more. It may have been decided elsewhere or its window closed.",
  "detail.decided": "Decided by",

  "block.not_pending": "This approval is no longer pending.",
  "block.not_named": "You aren't a named approver for this rule, so you can't decide it.",
  "block.self": "You requested an operation in this group, so another approver has to decide it.",

  "confirm.approveExchange": "Approve this exchange?",
  "confirm.approveOperation.one": "Approve {count} operation?",
  "confirm.approveOperation.other": "Approve {count} operations?",
  "confirm.reject": "Reject this request?",
  "confirm.recipient": "Recipient",
  "confirm.scope": "Scope",
  "confirm.exchangeRecipient": "Agent {requester}",
  "confirm.exchangeScope": "One delivery of {secret}",
  "confirm.operationRecipient": "Broker on {node}",
  "confirm.operationScope": "{action} for {unit} as {account} ({mode})",
  "confirm.rejectBody": "The requester is told the request was rejected. A decision can't be undone.",
  "confirm.approveBody": "The controller checks the latest state before recording your decision. A decision can't be undone.",
  "confirm.cancel": "Cancel",
  "confirm.approve": "Approve",
  "confirm.rejectAction": "Reject",
  "confirm.checking": "Checking the latest state…",
  "confirm.sending": "Recording decision…",
  "confirm.changed": "This approval changed since you opened it. Review it again before deciding.",
  "confirm.unknown": "The controller didn't confirm the decision. Nothing is resent automatically; check the approval's status before trying again.",

  "result.approved": "Approved. The controller recorded your decision.",
  "result.rejected": "Rejected. The controller recorded your decision.",
  "result.gone": "This approval was already decided or has expired.",
  "result.scope": "The controller refused: this approval isn't assigned to you.",
  "result.self": "The controller refused: you can't decide an approval that includes your own request.",
  "result.failed": "The decision wasn't recorded ({code}).",

  "lock.title": "Locked",
  "lock.body": "Decisions lock after 10 minutes without activity in this window. Enter your password to continue. The pending count keeps updating while locked.",
  "lock.unlock": "Unlock",
  "lock.working": "Checking…"
};

var vi = {
  "app.title": "Phê duyệt BlindPass",
  "app.surface": "Phê duyệt",
  "app.metadataOnly": "Ứng dụng này chỉ đọc siêu dữ liệu của yêu cầu. Nó không bao giờ nhận giá trị bí mật.",
  "language.label": "Ngôn ngữ",

  "signIn.title": "Đăng nhập để quyết định phê duyệt",
  "signIn.body": "Mã truy cập chỉ nằm trong bộ nhớ của ứng dụng này. Mã làm mới được lưu trong thư mục runtime của bạn, chỉ tài khoản người dùng của bạn đọc được, cho đến khi bạn đăng xuất.",
  "signIn.controller": "Bộ điều khiển",
  "signIn.controllerHint": "Địa chỉ https:// của bộ điều khiển BlindPass. http:// chỉ được chấp nhận cho máy này.",
  "signIn.username": "Tên đăng nhập",
  "signIn.password": "Mật khẩu",
  "signIn.usernameRequired": "Hãy nhập tên đăng nhập.",
  "signIn.passwordRequired": "Hãy nhập mật khẩu.",
  "signIn.submit": "Đăng nhập",
  "signIn.working": "Đang đăng nhập…",
  "signIn.invalid": "Tên đăng nhập hoặc mật khẩu không đúng.",
  "signIn.changePassword": "Mật khẩu của bạn là tạm thời. Hãy đổi nó trong bảng điều khiển rồi đăng nhập tại đây.",
  "signIn.signedOut": "Bạn đã đăng xuất. Phiên đã được kết thúc trên bộ điều khiển.",
  "signIn.signedOutLocal": "Bạn đã đăng xuất tại đây nhưng không báo được cho bộ điều khiển. Phiên sẽ tự kết thúc trong vòng 20 phút kể từ lần làm mới cuối.",
  "signIn.expired": "Phiên của bạn đã kết thúc trên bộ điều khiển. Hãy đăng nhập lại.",
  "signIn.otherController": "Một phiên đã lưu thuộc về bộ điều khiển khác. Nó đã bị xóa mà không được gửi đi đâu.",
  "signIn.storeFailed": "Đã đăng nhập nhưng không lưu được mã làm mới. Bạn sẽ phải đăng nhập lại sau khi khởi động lại ứng dụng.",

  "url.empty": "Hãy nhập địa chỉ bộ điều khiển.",
  "url.invalid": "Địa chỉ này không hợp lệ.",
  "url.scheme": "Hãy dùng https://. http:// chỉ được chấp nhận cho 127.0.0.1, localhost hoặc [::1].",
  "url.credentials": "Hãy bỏ tên người dùng hoặc mật khẩu khỏi địa chỉ.",
  "url.path": "Chỉ nhập giao thức, máy chủ và cổng, không có đường dẫn.",

  "trust.verified": "Chứng chỉ và tên máy chủ đã được xác minh bằng kho tin cậy của hệ thống",
  "trust.loopback": "Bộ điều khiển cục bộ qua http, chỉ trên máy này",
  "session.signedInAs": "Đăng nhập với tên {user}",
  "session.signOut": "Đăng xuất",
  "session.lock": "Khóa",

  "errors.tls": "Không xác minh được chứng chỉ của bộ điều khiển cho địa chỉ này, nên kết nối đã bị đóng trước khi gửi bất cứ thứ gì.",
  "errors.network": "Không kết nối được tới bộ điều khiển.",
  "errors.timeout": "Bộ điều khiển không trả lời kịp.",
  "errors.redirect": "Bộ điều khiển trả về một chuyển hướng. Ứng dụng này không đi theo chuyển hướng nên không gửi thêm gì. Hãy dùng địa chỉ trực tiếp của bộ điều khiển.",
  "errors.scheme": "Địa chỉ này dùng giao thức mà ứng dụng không cho phép.",
  "errors.noFleet": "Bộ điều khiển này không cung cấp phê duyệt đội máy.",
  "errors.rateLimited": "Quá nhiều lần thử. Hãy đợi một lát rồi thử lại.",
  "errors.unavailable": "Bộ điều khiển không hoàn tất được yêu cầu. Hãy thử lại sau ít phút.",
  "errors.forbidden": "Vai trò của bạn không được phép quyết định phê duyệt.",
  "errors.offline": "Không kết nối được bộ điều khiển. Đang hiển thị dữ liệu tải lần cuối; việc quyết định tạm dừng.",

  "queue.title": "Đang chờ bạn",
  "queue.count.one": "{count} đang chờ",
  "queue.count.other": "{count} đang chờ",
  "queue.empty": "Không có gì đang chờ bạn.",
  "queue.emptyBody": "Yêu cầu mới xuất hiện ở đây trong vòng 15 giây khi cửa sổ này đang mở.",
  "queue.updated": "Cập nhật lúc {time}",
  "queue.refresh": "Làm mới",
  "queue.loading": "Đang tải phê duyệt…",
  "queue.more": "Còn nhiều phê duyệt hơn danh sách này. Hãy quyết định những mục này trước hoặc dùng bảng điều khiển.",

  "kind.exchange": "Trao đổi bí mật",
  "kind.operation": "Thao tác đội máy",
  "status.pending": "Đang chờ",
  "status.approved": "Đã phê duyệt",
  "status.rejected": "Đã từ chối",
  "status.expired": "Đã hết hạn",
  "mode.file": "tệp",
  "mode.socket": "socket",

  "row.exchange": "{requester} yêu cầu {secret}",
  "row.operation": "{action} cho {unit}",
  "row.closes": "Đóng sau {time}",
  "row.operations.one": "{count} thao tác",
  "row.operations.other": "{count} thao tác",

  "detail.back": "Quay lại danh sách",
  "detail.recipient": "Người nhận",
  "detail.scope": "Phạm vi",
  "detail.purpose": "Mục đích, do người yêu cầu viết",
  "detail.noPurpose": "Không nêu mục đích.",
  "detail.requester": "Người yêu cầu",
  "detail.node": "Máy",
  "detail.workload": "Workload",
  "detail.account": "Tài khoản",
  "detail.rule": "Quy tắc chính sách",
  "detail.approvers": "Người phê duyệt",
  "detail.members": "Các thao tác trong phê duyệt này",
  "detail.member": "{resource} · lần gọi {invocation} · bởi {requester}",
  "detail.closes": "Thời hạn quyết định đóng sau",
  "detail.closed": "Thời hạn quyết định đã đóng.",
  "detail.clockUnknown": "Đóng lúc {time} theo giờ bộ điều khiển",
  "detail.requested": "Yêu cầu lúc",
  "detail.approve": "Phê duyệt…",
  "detail.reject": "Từ chối…",
  "detail.notFound": "Phê duyệt này không còn nữa. Có thể nó đã được quyết định ở nơi khác hoặc đã hết thời hạn.",
  "detail.decided": "Quyết định bởi",

  "block.not_pending": "Phê duyệt này không còn ở trạng thái chờ.",
  "block.not_named": "Bạn không phải người phê duyệt được chỉ định cho quy tắc này nên không thể quyết định.",
  "block.self": "Bạn đã yêu cầu một thao tác trong nhóm này nên người phê duyệt khác phải quyết định.",

  "confirm.approveExchange": "Phê duyệt lần trao đổi này?",
  "confirm.approveOperation.one": "Phê duyệt {count} thao tác?",
  "confirm.approveOperation.other": "Phê duyệt {count} thao tác?",
  "confirm.reject": "Từ chối yêu cầu này?",
  "confirm.recipient": "Người nhận",
  "confirm.scope": "Phạm vi",
  "confirm.exchangeRecipient": "Tác tử {requester}",
  "confirm.exchangeScope": "Một lần giao {secret}",
  "confirm.operationRecipient": "Broker trên {node}",
  "confirm.operationScope": "{action} cho {unit} với tài khoản {account} ({mode})",
  "confirm.rejectBody": "Người yêu cầu sẽ được báo yêu cầu bị từ chối. Quyết định không thể hoàn tác.",
  "confirm.approveBody": "Bộ điều khiển kiểm tra trạng thái mới nhất trước khi ghi nhận quyết định. Quyết định không thể hoàn tác.",
  "confirm.cancel": "Hủy",
  "confirm.approve": "Phê duyệt",
  "confirm.rejectAction": "Từ chối",
  "confirm.checking": "Đang kiểm tra trạng thái mới nhất…",
  "confirm.sending": "Đang ghi nhận quyết định…",
  "confirm.changed": "Phê duyệt này đã thay đổi kể từ khi bạn mở. Hãy xem lại trước khi quyết định.",
  "confirm.unknown": "Bộ điều khiển không xác nhận quyết định. Không có gì được tự động gửi lại; hãy kiểm tra trạng thái phê duyệt trước khi thử lại.",

  "result.approved": "Đã phê duyệt. Bộ điều khiển đã ghi nhận quyết định của bạn.",
  "result.rejected": "Đã từ chối. Bộ điều khiển đã ghi nhận quyết định của bạn.",
  "result.gone": "Phê duyệt này đã được quyết định hoặc đã hết hạn.",
  "result.scope": "Bộ điều khiển từ chối: phê duyệt này không được giao cho bạn.",
  "result.self": "Bộ điều khiển từ chối: bạn không thể quyết định phê duyệt có yêu cầu của chính mình.",
  "result.failed": "Quyết định chưa được ghi nhận ({code}).",

  "lock.title": "Đã khóa",
  "lock.body": "Việc quyết định bị khóa sau 10 phút không có thao tác trong cửa sổ này. Hãy nhập mật khẩu để tiếp tục. Số lượng đang chờ vẫn được cập nhật khi khóa.",
  "lock.unlock": "Mở khóa",
  "lock.working": "Đang kiểm tra…"
};

var TABLES = { en: en, vi: vi };

function normalise(locale) {
  var base = String(locale || "en").toLowerCase().slice(0, 2);
  return LOCALES.indexOf(base) === -1 ? "en" : base;
}

/** Look up a string and fill {name} placeholders. Unknown keys return the key. */
function t(locale, key, args) {
  var table = TABLES[normalise(locale)];
  var value = table[key];
  if (value === undefined) value = en[key];
  if (value === undefined) return key;
  if (!args) return value;
  return value.replace(/\{(\w+)\}/g, function (match, name) {
    return args[name] === undefined || args[name] === null ? match : String(args[name]);
  });
}

/** Plural keys end in .one / .other; Vietnamese has one form. */
function tn(locale, key, count, args) {
  var merged = { count: count };
  for (var name in args || {}) merged[name] = args[name];
  return t(locale, key + (count === 1 ? ".one" : ".other"), merged);
}

function keys(locale) {
  return Object.keys(TABLES[normalise(locale)]);
}
