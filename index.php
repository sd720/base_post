<?php
// index.php — Single-file LinkedIn-like clone (improved)
// Requirements: PHP CLI or PHP-enabled host with pdo_sqlite & sqlite3 enabled.
// Run locally: php -S localhost:8000
// File auto-creates data.sqlite and uploads/ folder.
//
// Features: Signup/Login (hashed), CSRF, create post (text + image), edit/delete own posts,
// likes, demo user + sample posts seeding, image validation (2MB), sanitized filenames,
// session hardening, client-side validation + image preview, pagination ("Load more"),
// improved responsive UI and README included below (printed to console on first run).
echo "<!-- CURRENT FILE: " . __FILE__ . " -->";



// -------------------- Configuration --------------------
$db_file = __DIR__ . '/data.sqlite';
$upload_dir = __DIR__ . '/uploads';
$site_name = "MiniLinked";
$max_image_bytes = 2 * 1024 * 1024; // 2 MB
$allowed_ext = ['jpg','jpeg','png','gif','webp'];
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',      // default
    'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Lax'
]);
if (!is_dir($upload_dir)) mkdir($upload_dir, 0755, true);
session_start();

// -------------------- Helpers --------------------
function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES); }

function current_user(){
    if (!empty($_SESSION['user'])) return $_SESSION['user'];
    return null;
}

function flash($msg, $type='info'){
    $_SESSION['flash'] = ['msg'=>$msg,'type'=>$type];
}

function get_flash(){
    if (!empty($_SESSION['flash'])){ $f = $_SESSION['flash']; unset($_SESSION['flash']); return $f; }
    return null;
}

function redirect($url){ header("Location: $url"); exit; }

function gen_csrf(){
    if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(24));
    return $_SESSION['csrf_token'];
}

function verify_csrf($token){
    return !empty($token) && !empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'],$token);
}

function sanitize_filename($name){
    // remove path, spaces, non-alphanum, keep dot and dash
    $name = preg_replace('/[^A-Za-z0-9\.\-_]/', '_', basename($name));
    return substr($name, 0, 200);
}

// -------------------- DB Setup --------------------
try {
    $db = new PDO('sqlite:' . $db_file);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $db->exec("PRAGMA foreign_keys = ON;");
    // users
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );");
    // posts
    $db->exec("CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        text TEXT,
        image TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );");
    // likes
    $db->exec("CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, post_id)
    );");
    // seed demo user & sample posts if empty
    $count = intval($db->query("SELECT COUNT(*) FROM users")->fetchColumn());
    if ($count === 0){
        $pw = password_hash('Demo@123', PASSWORD_DEFAULT);
        $db->prepare("INSERT INTO users (name,email,password) VALUES (:n,:e,:p)")
           ->execute([':n'=>'Demo User',':e'=>'demo@demo.com',':p'=>$pw]);
        $uid = intval($db->lastInsertId());
        $stmt = $db->prepare("INSERT INTO posts (user_id,text) VALUES (:uid,:t)");
        $stmt->execute([':uid'=>$uid,':t'=>"Welcome to MiniLinked — this demo user was created automatically."]);
        $stmt->execute([':uid'=>$uid,':t'=>"Try creating a post, uploading an image (<=2MB), liking, editing or deleting your own posts."]);
        // optional: create another sample user
        $pw2 = password_hash('Password1!', PASSWORD_DEFAULT);
        $db->prepare("INSERT INTO users (name,email,password) VALUES (:n,:e,:p)")
           ->execute([':n'=>'Alice',':e'=>'alice@demo.com',':p'=>$pw2]);
        $alice = intval($db->lastInsertId());
        $db->prepare("INSERT INTO posts (user_id,text) VALUES (:uid,:t)")
           ->execute([':uid'=>$alice,':t'=>"Alice here — hello! This shows multiple users' posts."]);
        // print lightweight README to server console
        if (php_sapi_name() === 'cli-server'){
            fwrite(STDERR, "MiniLinked demo created. Demo credentials: demo@demo.com / Demo@123\n");
        }
    }
} catch (Exception $e){
    die("DB error: " . h($e->getMessage()));
}

// -------------------- Actions --------------------
$action = $_REQUEST['action'] ?? 'home';

// REGISTER
if ($action === 'register' && $_SERVER['REQUEST_METHOD'] === 'POST'){
    if (!verify_csrf($_POST['csrf'] ?? '')) { flash("Invalid request (CSRF)","danger"); redirect('?'); }
    $name = trim($_POST['name'] ?? '');
    $email = strtolower(trim($_POST['email'] ?? ''));
    $password = $_POST['password'] ?? '';
    if (!$name || !$email || !$password){ flash("Please fill all fields","danger"); redirect('?action=register_form'); }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)){ flash("Invalid email","danger"); redirect('?action=register_form'); }
    if (strlen($password) < 6){ flash("Password must be >=6 chars","danger"); redirect('?action=register_form'); }
    // check existing
    $stmt = $db->prepare("SELECT id FROM users WHERE email=:email"); $stmt->execute([':email'=>$email]);
    if ($stmt->fetch()){ flash("Email already registered","danger"); redirect('?action=register_form'); }
    $hash = password_hash($password, PASSWORD_DEFAULT);
    $db->prepare("INSERT INTO users (name,email,password) VALUES (:n,:e,:p)")
       ->execute([':n'=>$name,':e'=>$email,':p'=>$hash]);
    $uid = intval($db->lastInsertId());
    $_SESSION['user'] = ['id'=>$uid,'name'=>$name,'email'=>$email];
    flash("Welcome, $name","success");
    redirect('?');
}

// LOGIN
if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST'){
    if (!verify_csrf($_POST['csrf'] ?? '')) { flash("Invalid request (CSRF)","danger"); redirect('?'); }
    $email = strtolower(trim($_POST['email'] ?? ''));
    $password = $_POST['password'] ?? '';
    if (!$email || !$password){ flash("Fill email/password","danger"); redirect('?action=login'); }
    $stmt = $db->prepare("SELECT id,name,email,password FROM users WHERE email=:email"); $stmt->execute([':email'=>$email]);
    $u = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$u || !password_verify($password, $u['password'])){ flash("Invalid credentials","danger"); redirect('?action=login'); }
    $_SESSION['user'] = ['id'=>$u['id'],'name'=>$u['name'],'email'=>$u['email']];
    flash("Logged in as " . $u['name'], 'success');
    redirect('?');
}

// LOGOUT
if ($action === 'logout'){ session_unset(); session_destroy(); session_start(); flash("Logged out","info"); redirect('?'); }

// CREATE POST
if ($action === 'create_post' && $_SERVER['REQUEST_METHOD'] === 'POST'){
    if (!verify_csrf($_POST['csrf'] ?? '')) { flash("Invalid request (CSRF)","danger"); redirect('?'); }
    $user = current_user(); if (!$user) { flash("Login required","danger"); redirect('?'); }
    $text = trim($_POST['text'] ?? '');
    if ($text === '' && empty($_FILES['image']['name'])) { flash("Text or image required","danger"); redirect('?'); }
    $uploaded_path = null;
    if (!empty($_FILES['image']['name'])){
        $f = $_FILES['image'];
        if ($f['error'] !== UPLOAD_ERR_OK){ flash("Upload error","danger"); redirect('?'); }
        if ($f['size'] > $max_image_bytes){ flash("Image too large (max 2MB)","danger"); redirect('?'); }
        $ext = strtolower(pathinfo($f['name'], PATHINFO_EXTENSION));
        if (!in_array($ext, $allowed_ext)){ flash("Invalid image type","danger"); redirect('?'); }
        $fn = uniqid('img_') . '-' . sanitize_filename($f['name']);
        $dest = $upload_dir . DIRECTORY_SEPARATOR . $fn;
        if (!move_uploaded_file($f['tmp_name'], $dest)){ flash("Failed to save upload","danger"); redirect('?'); }
        $uploaded_path = 'uploads/' . $fn;
    }
    $stmt = $db->prepare("INSERT INTO posts (user_id,text,image) VALUES (:uid,:text,:img)");
    $stmt->execute([':uid'=>$user['id'],':text'=>$text,':img'=>$uploaded_path]);
    flash("Post created","success");
    redirect('?');
}

// DELETE POST
if ($action === 'delete_post' && !empty($_GET['id'])){
    $user = current_user(); if (!$user) { flash("Login required","danger"); redirect('?'); }
    $id = intval($_GET['id']);
    $stmt = $db->prepare("SELECT user_id,image FROM posts WHERE id=:id"); $stmt->execute([':id'=>$id]);
    $post = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$post){ flash("Post not found","danger"); redirect('?'); }
    if ($post['user_id'] != $user['id']){ flash("Unauthorized","danger"); redirect('?'); }
    if ($post['image']){ @unlink(__DIR__ . '/' . $post['image']); }
    $db->prepare("DELETE FROM posts WHERE id=:id")->execute([':id'=>$id]);
    flash("Post deleted","info");
    redirect('?');
}

// EDIT POST
if ($action === 'edit_post' && $_SERVER['REQUEST_METHOD'] === 'POST'){
    if (!verify_csrf($_POST['csrf'] ?? '')) { flash("Invalid request (CSRF)","danger"); redirect('?'); }
    $user = current_user(); if (!$user) { flash("Login required","danger"); redirect('?'); }
    $id = intval($_POST['id'] ?? 0);
    $text = trim($_POST['text'] ?? '');
    if ($text === ''){ flash("Text required","danger"); redirect('?'); }
    $stmt = $db->prepare("SELECT user_id FROM posts WHERE id=:id"); $stmt->execute([':id'=>$id]); $p = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$p){ flash("Not found","danger"); redirect('?'); }
    if ($p['user_id'] != $user['id']){ flash("Unauthorized","danger"); redirect('?'); }
    $db->prepare("UPDATE posts SET text=:text WHERE id=:id")->execute([':text'=>$text,':id'=>$id]);
    flash("Post updated","success");
    redirect('?');
}

// LIKE / UNLIKE
if ($action === 'like' && !empty($_GET['id'])) {
    $user = current_user(); if (!$user) { flash("Login required","danger"); redirect('?'); }
    $post_id = intval($_GET['id']);
    try {
        $db->prepare("INSERT INTO likes (user_id,post_id) VALUES (:uid,:pid)")
           ->execute([':uid'=>$user['id'],':pid'=>$post_id]);
    } catch (Exception $e) { /* ignore duplicate */ }
    redirect('?');
}
if ($action === 'unlike' && !empty($_GET['id'])) {
    $user = current_user(); if (!$user) { flash("Login required","danger"); redirect('?'); }
    $post_id = intval($_GET['id']);
    $db->prepare("DELETE FROM likes WHERE user_id=:uid AND post_id=:pid")
       ->execute([':uid'=>$user['id'],':pid'=>$post_id]);
    redirect('?');
}

// -------------------- Rendering (frontend) --------------------
$flash = get_flash();
$csrf = gen_csrf();
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title><?php echo h($site_name); ?></title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
:root{--accent:#0b63d6;--muted:#666;--bg:#f6f7fb}
*{box-sizing:border-box}
body{font-family:Inter,system-ui,Arial,sans-serif;margin:0;background:var(--bg);color:#111}
.nav{background:white;padding:12px 16px;display:flex;align-items:center;gap:12px;border-bottom:1px solid #eee;position:sticky;top:0;z-index:6}
.brand{font-weight:700;color:var(--accent);font-size:18px}
.container{max-width:900px;margin:20px auto;padding:0 16px}
.card{background:white;padding:14px;border-radius:12px;box-shadow:0 6px 18px rgba(13,38,76,0.04);margin-bottom:14px}
.row{display:flex;gap:12px;align-items:center}
input, textarea{width:100%;padding:10px;border:1px solid #e3e6ee;border-radius:10px;font-size:14px}
button{background:var(--accent);color:white;border:0;padding:8px 14px;border-radius:10px;cursor:pointer;font-weight:600}
.muted{color:var(--muted);font-size:13px}
.small{font-size:13px}
.post-image{max-width:100%;border-radius:10px;margin-top:8px}
.topbar-right{margin-left:auto;display:flex;gap:8px;align-items:center}
.link-btn{background:transparent;border:0;color:var(--accent);cursor:pointer;font-weight:600}
.flash{padding:12px;border-radius:10px;margin-bottom:12px}
.flash.info{background:#eef6ff;color:#0b63d6}
.flash.success{background:#e6ffef;color:#0b7a3a}
.flash.danger{background:#ffeef0;color:#b00020}
.meta{color:#555;font-size:12px}
.card .controls{display:flex;gap:10px;margin-top:8px}
@media(max-width:640px){.row{flex-direction:column;align-items:stretch}.topbar-right{display:none}}
.footer{padding:16px;text-align:center;color:#777;font-size:13px}
.preview-img{max-height:120px;border-radius:8px;object-fit:cover}
.load-more{display:block;margin:0 auto;background:#fff;border:1px solid #e3e6ee;color:var(--accent);padding:8px 12px;border-radius:8px}
</style>
</head>
<body>
<nav class="nav">
    <div class="brand"><?php echo h($site_name); ?></div>
    <a href="?">Feed</a>
    <?php if (current_user()): ?>
        <a href="?action=create">Create</a>
    <?php endif; ?>
    <div class="topbar-right">
        <?php if (current_user()): ?>
            <div class="muted">Hi, <?php echo h(current_user()['name']); ?></div>
            <a class="link-btn" href="?action=logout">Logout</a>
        <?php else: ?>
            <a href="?action=login">Login</a>
            <a href="?action=register_form">Signup</a>
        <?php endif; ?>
    </div>
</nav>

<div class="container">
    <?php if ($flash): ?>
        <div class="flash <?php echo h($flash['type']); ?>"><?php echo h($flash['msg']); ?></div>
    <?php endif; ?>

<?php
// Register form
if ($action === 'register_form'):
?>
    <div class="card">
        <h2>Create account</h2>
        <form method="post" action="?action=register" onsubmit="return validateRegister(this)">
            <input type="hidden" name="csrf" value="<?php echo h($csrf); ?>">
            <div style="margin-bottom:8px"><label class="small">Name</label><input name="name" required></div>
            <div style="margin-bottom:8px"><label class="small">Email</label><input name="email" type="email" required></div>
            <div style="margin-bottom:8px"><label class="small">Password</label><input name="password" type="password" required></div>
            <div class="row" style="margin-top:8px"><button type="submit">Create account</button><a href="?" style="margin-left:12px" class="muted">Back</a></div>
        </form>
    </div>
<?php
    exit;
endif;

// Login form
if ($action === 'login'):
?>
    <div class="card">
        <h2>Login</h2>
        <form method="post" action="?action=login">
            <input type="hidden" name="csrf" value="<?php echo h($csrf); ?>">
            <div style="margin-bottom:8px"><label class="small">Email</label><input name="email" type="email" required></div>
            <div style="margin-bottom:8px"><label class="small">Password</label><input name="password" type="password" required></div>
            <div class="row" style="margin-top:8px"><button type="submit">Login</button><a href="?action=register_form" style="margin-left:12px" class="muted">Sign up</a></div>
            <p class="muted small" style="margin-top:8px">Demo: <strong>demo@demo.com</strong> / <strong>Demo@123</strong></p>
        </form>
    </div>
<?php
    exit;
endif;

// Create page (full composer)
if ($action === 'create'){
    $u = current_user(); if (!$u){ flash("Login required","danger"); redirect('?'); }
?>
    <div class="card">
        <h2>Create Post</h2>
        <form method="post" action="?action=create_post" enctype="multipart/form-data" onsubmit="return validatePost(this)">
            <input type="hidden" name="csrf" value="<?php echo h($csrf); ?>">
            <div style="margin-bottom:8px"><label class="small">Text</label><textarea name="text" rows="5" placeholder="Share something..."></textarea></div>
            <div style="margin-bottom:8px"><label class="small">Image (optional, max 2MB)</label><input id="imageInput" type="file" name="image" accept="image/*" onchange="previewImage(event)"></div>
            <div id="previewBox" style="display:none"><img id="preview" class="preview-img"></div>
            <div class="row" style="margin-top:8px"><button type="submit">Post</button><a href="?" style="margin-left:12px" class="muted">Back to feed</a></div>
        </form>
    </div>
<?php
    exit;
}

// Feed (main) with pagination
$page = max(1, intval($_GET['page'] ?? 1));
$perPage = 6;
$offset = ($page - 1) * $perPage;
$stmt = $db->prepare("SELECT p.*, u.name as author_name,
    (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS like_count
    FROM posts p JOIN users u ON p.user_id = u.id
    ORDER BY p.created_at DESC LIMIT :lim OFFSET :off");
$stmt->bindValue(':lim', $perPage, PDO::PARAM_INT);
$stmt->bindValue(':off', $offset, PDO::PARAM_INT);
$stmt->execute();
$posts = $stmt->fetchAll(PDO::FETCH_ASSOC);

// count total
$total = intval($db->query("SELECT COUNT(*) FROM posts")->fetchColumn());
$more = ($offset + count($posts)) < $total;
?>

    <div class="card">
        <?php if (current_user()): ?>
            <form method="post" action="?action=create_post" enctype="multipart/form-data" onsubmit="return validatePost(this)">
                <input type="hidden" name="csrf" value="<?php echo h($csrf); ?>">
                <textarea name="text" rows="3" placeholder="Write a post..." style="margin-bottom:8px"></textarea>
                <div style="display:flex;gap:8px;align-items:center">
                    <input id="quickImg" type="file" name="image" accept="image/*" onchange="previewImage(event)">
                    <button type="submit">Post</button>
                    <a href="?action=create" style="margin-left:8px" class="muted">Open full composer</a>
                </div>
                <div id="previewBoxQuick" style="display:none;margin-top:8px"><img id="previewQuick" class="preview-img"></div>
            </form>
        <?php else: ?>
            <div class="row"><div class="muted">Log in or sign up to create posts.</div></div>
        <?php endif; ?>
    </div>

    <div style="margin-top:8px">
        <?php if (count($posts) === 0): ?>
            <div class="card"><div class="muted">No posts yet — try creating one!</div></div>
        <?php else: foreach ($posts as $p): ?>
            <div class="card">
                <div class="row" style="justify-content:space-between">
                    <div>
                        <strong><a href="?user=<?php echo $p['user_id']; ?>"><?php echo h($p['author_name']); ?></a></strong>
                        <div class="meta"><?php echo h(date("M j, Y H:i", strtotime($p['created_at']))); ?></div>
                    </div>
                    <div class="muted small">
                        <?php echo intval($p['like_count']) . ' like' . (intval($p['like_count']) !== 1 ? 's' : ''); ?>
                    </div>
                </div>
                <p style="margin-top:10px;white-space:pre-wrap"><?php echo nl2br(h($p['text'])); ?></p>
                <?php if ($p['image']): ?><img src="<?php echo h($p['image']); ?>" class="post-image" alt="post image"><?php endif; ?>

                <div class="controls">
                    <?php if (current_user()):
                        $stmt2 = $db->prepare("SELECT id FROM likes WHERE user_id=:uid AND post_id=:pid");
                        $stmt2->execute([':uid'=>current_user()['id'],':pid'=>$p['id']]);
                        $liked = $stmt2->fetch();
                        if ($liked): ?>
                            <a class="link-btn" href="?action=unlike&id=<?php echo $p['id']; ?>">Unlike</a>
                        <?php else: ?>
                            <a class="link-btn" href="?action=like&id=<?php echo $p['id']; ?>">Like</a>
                        <?php endif; ?>
                    <?php endif; ?>

                    <?php if (current_user() && current_user()['id'] == $p['user_id']): ?>
                        <a href="#" onclick="showEdit(<?php echo $p['id']; ?>);return false;" class="link-btn">Edit</a>
                        <a href="?action=delete_post&id=<?php echo $p['id']; ?>" onclick="return confirm('Delete this post?')" style="color:#b00020">Delete</a>
                    <?php endif; ?>
                </div>

                <?php if (current_user() && current_user()['id'] == $p['user_id']): ?>
                    <form id="edit-form-<?php echo $p['id']; ?>" method="post" action="?action=edit_post" style="display:none;margin-top:10px" onsubmit="return validateEdit(this)">
                        <input type="hidden" name="csrf" value="<?php echo h($csrf); ?>">
                        <input type="hidden" name="id" value="<?php echo $p['id']; ?>">
                        <textarea name="text" rows="3"><?php echo h($p['text']); ?></textarea>
                        <div style="margin-top:6px"><button type="submit">Save</button> <a href="#" onclick="hideEdit(<?php echo $p['id']; ?>);return false;" style="margin-left:8px" class="muted">Cancel</a></div>
                    </form>
                <?php endif; ?>
            </div>
        <?php endforeach; endif; ?>
    </div>

    <?php if ($more): ?>
        <a class="load-more" href="?page=<?php echo ($page+1); ?>">Load more</a>
    <?php endif; ?>

</div> <!-- container -->

<footer class="footer">
    Built with PHP + SQLite • Single-file demo • <?php echo date('Y'); ?>
</footer>

<script>
// Client-side JS: validation & preview
function validateRegister(f){
    if (!f.name.value.trim() || !f.email.value.trim() || !f.password.value) { alert('Fill all fields'); return false; }
    if (f.password.value.length < 6){ alert('Password >= 6 chars'); return false; }
    return true;
}
function validatePost(f){
    // ensure text or image present
    var text = (f.text && f.text.value.trim()) || '';
    var img = (f.image && f.image.files && f.image.files.length) ? f.image.files[0] : null;
    if (!text && !img){ alert('Write something or attach an image'); return false; }
    if (img && img.size > <?php echo $max_image_bytes; ?>){ alert('Image too large (max 2MB)'); return false; }
    return true;
}
function validateEdit(f){ if (!f.text.value.trim()){ alert('Text required'); return false; } return true; }

function previewImage(ev){
    var file = ev.target.files[0];
    var box = document.getElementById('previewBox') || document.getElementById('previewBoxQuick');
    var img = document.getElementById('preview') || document.getElementById('previewQuick');
    if (!file) { if (box) box.style.display='none'; return; }
    if (file.size > <?php echo $max_image_bytes; ?>){ alert('Image too large (max 2MB)'); ev.target.value=''; return; }
    var reader = new FileReader();
    reader.onload = function(e){ if (img){ img.src = e.target.result; if (box) box.style.display='block'; } }
    reader.readAsDataURL(file);
}

function showEdit(id){ document.getElementById('edit-form-'+id).style.display='block'; }
function hideEdit(id){ document.getElementById('edit-form-'+id).style.display='none'; }
</script>
</body>
</html>
