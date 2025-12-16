require 'webrick'
require 'json'
require 'securerandom'
require 'openssl'

PORT = (ENV['PORT'] || '5050').to_i
ALLOWED_ORIGINS = ['http://localhost:8000','http://127.0.0.1:8000','https://duobuddy.my','http://duobuddy.my']
DATA_DIR = File.join(__dir__, 'data')
USERS_FILE = File.join(DATA_DIR, 'users.json')

SESSIONS = {}
LOGIN_ATTEMPTS = {}

def ensure_data
  Dir.mkdir(DATA_DIR) unless Dir.exist?(DATA_DIR)
  unless File.exist?(USERS_FILE)
    admin = create_user_object({
      name: 'Administrator',
      email: 'admin@duobuddy.my',
      username: 'systemadmin',
      phone: '+60 12-000 0000',
      password: 'Admin@123!',
      is_admin: true,
      data: { jobTitle: 'Administrator', company: 'DuoBuddy', about: 'System Administrator', created: Time.now.iso8601 }
    })
    File.write(USERS_FILE, JSON.pretty_generate([admin]))
  end
end

def read_users
  ensure_data
  JSON.parse(File.read(USERS_FILE))
rescue
  []
end

def write_users(users)
  File.write(USERS_FILE, JSON.pretty_generate(users))
end

def hash_password(password, salt=nil)
  salt ||= SecureRandom.hex(16)
  digest = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, 100_000, 32, 'sha256').unpack1('H*')
  { 'salt' => salt, 'hash' => digest }
end

def create_user_object(fields)
  hp = hash_password(fields[:password])
  {
    '__backendId' => SecureRandom.hex(8),
    'name' => fields[:name],
    'email' => fields[:email],
    'username' => fields[:username],
    'phone' => fields[:phone],
    'is_admin' => !!fields[:is_admin],
    'passwordSalt' => hp['salt'],
    'passwordHash' => hp['hash'],
    'deleted' => false,
    'data' => (fields[:data].is_a?(String) ? fields[:data] : JSON.dump(fields[:data] || { created: Time.now.iso8601, cards: [] }))
  }
end

def sanitize_user(u)
  u.reject { |k,_| ['passwordHash','passwordSalt'].include?(k) }
end

def set_cors(req, res)
  origin = req.header['origin']&.first
  origin = ALLOWED_ORIGINS.include?(origin) ? origin : ALLOWED_ORIGINS.first
  res['Access-Control-Allow-Origin'] = origin
  res['Access-Control-Allow-Credentials'] = 'true'
  res['Access-Control-Allow-Headers'] = 'Content-Type'
  res['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
end

def set_json(res)
  res['Content-Type'] = 'application/json'
end

def parse_body(req)
  begin
    JSON.parse(req.body || '{}')
  rescue
    {}
  end
end

server = WEBrick::HTTPServer.new(Port: PORT, AccessLog: [], Logger: WEBrick::Log::new($stdout, WEBrick::Log::INFO))

# Serve main app file explicitly and redirect root to DuoBuddy.html to avoid index.html mismatch
server.mount_proc '/' do |req, res|
  if req.path == '/' || req.path.empty?
    res.status = 302
    res['Location'] = '/index.html'
  else
    spa_paths = %r{^/(login|signup|admin|company-management|my-cards|profile|edit-profile|change-password)$}
    profile_path = %r{^/profile/[^/]+$}
    company_path = %r{^/company/[^/]+$}
    if req.path =~ spa_paths || req.path =~ profile_path || req.path =~ company_path
      index = File.join(Dir.pwd, 'index.html')
      res['Content-Type'] = 'text/html'
      res.body = File.file?(index) ? File.binread(index) : '<!doctype html><html><body>Index not found</body></html>'
    else
      # For any other static path, attempt to read and serve the file
      path = File.join(Dir.pwd, req.path.sub(/^\//, ''))
      if File.file?(path)
        res['Content-Type'] = WEBrick::HTTPUtils.mime_type(path, WEBrick::HTTPUtils::DefaultMimeTypes)
        res.body = File.binread(path)
      else
        res.status = 404
        res['Content-Type'] = 'text/plain'
        res.body = 'Not Found'
      end
    end
  end
end

def valid_password?(pwd)
  return false if pwd.nil? || pwd.strip.length < 7
  return false unless pwd =~ /[^A-Za-z0-9]/
  banned = %w[123456 654321 1234567 7654321 password qwerty 123 abc123]
  return false if banned.include?(pwd.downcase)
  true
end

server.mount_proc '/api/auth/signup' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  body = parse_body(req)
  name,email,username,password,phone = body.values_at('name','email','username','password','phone')
  if [name,email,username,password].any? { |v| v.to_s.strip.empty? }
    res.status = 400; res.body = { error: 'invalid' }.to_json; next
  end
  unless valid_password?(password)
    res.status = 400; res.body = { error: 'weak_password' }.to_json; next
  end
  users = read_users
  if users.any? { |u| u['email'] == email || u['username'].to_s.downcase == username.to_s.downcase }
    res.status = 409; res.body = { error: 'exists' }.to_json; next
  end
  now = Time.now
  trial_end = (now + 24*60*60).iso8601
  user = create_user_object({ name: name, email: email, username: username, phone: phone, password: password, is_admin: false, data: { jobTitle: '', company: '', about: '', created: now.iso8601, trialEnd: trial_end, cards: [] } })
  users << user
  write_users(users)
  res.body = { ok: true }.to_json
end

server.mount_proc '/api/auth/login' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  begin
    ip = (req.respond_to?(:remote_ip) && req.remote_ip) || (req.peeraddr && req.peeraddr[3]) || 'unknown'
    now = Time.now.to_i
    st = LOGIN_ATTEMPTS[ip] || { count: 0, window: now }
    if now - st[:window] > 300
      st = { count: 0, window: now }
    end
    if st[:count] >= 10
      res.status = 429; res.body = { error: 'too_many_attempts' }.to_json; next
    end
    st[:count] += 1
    LOGIN_ATTEMPTS[ip] = st
  rescue
  end
  body = parse_body(req)
  email,password = body.values_at('email','password')
  users = read_users
  user = users.find { |u| u['email'].to_s.downcase == email.to_s.downcase }
  unless user
    res.status = 401; res.body = { error: 'invalid' }.to_json; next
  end
  hp = hash_password(password, user['passwordSalt'])
  if hp['hash'] != user['passwordHash']
    res.status = 401; res.body = { error: 'invalid' }.to_json; next
  end
  sid = SecureRandom.hex(16)
  SESSIONS[sid] = user['__backendId']
  origin = req.header['origin']&.first
  secure = origin && origin.start_with?('https://')
  res['Set-Cookie'] = "sid=#{sid}; HttpOnly; Path=/; SameSite=Lax#{secure ? '; Secure' : ''}"
  res.body = { user: sanitize_user(user) }.to_json
end

server.mount_proc '/api/auth/logout' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  SESSIONS.delete(sid) if sid
  origin = req.header['origin']&.first
  secure = origin && origin.start_with?('https://')
  res['Set-Cookie'] = "sid=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax#{secure ? '; Secure' : ''}"
  res.body = { ok: true }.to_json
end

# Auth: change password
server.mount_proc '/api/auth/change_password' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  users = read_users
  uid = sid && SESSIONS[sid]
  user = uid && users.find { |u| u['__backendId'] == uid }
  unless user
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  current = body['currentPassword'].to_s
  new_pwd = body['newPassword'].to_s
  hp = hash_password(current, user['passwordSalt'])
  if hp['hash'] != user['passwordHash']
    res.status = 400; res.body = { error: 'invalid_current' }.to_json; next
  end
  unless valid_password?(new_pwd)
    res.status = 400; res.body = { error: 'weak_password' }.to_json; next
  end
  nh = hash_password(new_pwd)
  user['passwordSalt'] = nh['salt']
  user['passwordHash'] = nh['hash']
  write_users(users)
  res.body = { ok: true }.to_json
end

server.mount_proc '/api/users/me' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  users = read_users
  uid = sid && SESSIONS[sid]
  user = uid && users.find { |u| u['__backendId'] == uid }
  res.body = { user: user ? sanitize_user(user) : nil }.to_json
end

server.mount_proc '/api/profile' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  # /api/profile/<username>
  username = req.path.sub('/api/profile/', '')
  users = read_users
  user = users.find { |u| u['username'] && u['username'].downcase == username.downcase }
  if !user || user['deleted']
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  res.body = { user: sanitize_user(user) }.to_json
end

server.mount_proc '/api/cards/order' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  unless uid
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  slot,design,quantity,address,notes,paymentProof,designImage,qrType,qrText,showPhoneOnCard,nameText,phoneText = body.values_at('slot','design','quantity','address','notes','paymentProof','designImage','qrType','qrText','showPhoneOnCard','nameText','phoneText')
  users = read_users
  user = users.find { |u| u['__backendId'] == uid }
  profile = user['data'] ? JSON.parse(user['data']) : {}
  cards = profile['cards'] || []
  card = cards.find { |c| c['slot'] == slot }
  now = Time.now.iso8601
  if card
    card['ordered'] = false
    card['design'] = design
    card['quantity'] = quantity
    card['orderDate'] = now
    card['paymentProof'] = paymentProof
    card['address'] = address
    card['notes'] = notes
    card['status'] = 'pending_approval'
    card['designImage'] = designImage if designImage
    card['qrType'] = qrType if qrType
    card['qrText'] = qrText if qrText
    card['showPhoneOnCard'] = !!showPhoneOnCard
    card['nameText'] = nameText if nameText
    card['phoneText'] = phoneText if phoneText
  else
    cards << { 'slot' => slot, 'ordered' => false, 'design' => design, 'quantity' => quantity, 'orderDate' => now, 'paymentProof' => paymentProof, 'address' => address, 'notes' => notes, 'status' => 'pending_approval', 'designImage' => designImage, 'qrType' => qrType, 'qrText' => qrText, 'showPhoneOnCard' => !!showPhoneOnCard, 'nameText' => nameText, 'phoneText' => phoneText }
  end
  profile['cards'] = cards
  user['data'] = JSON.dump(profile)
  write_users(users)
  res.body = { user: sanitize_user(user) }.to_json
end

 
# Admin: list users (purge deleted > 7 days)
server.mount_proc '/api/admin/users' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  # purge
  now = Time.now
  pruned = users.reject do |u|
    if u['deleted'] && u['deletedAt']
      begin
        del = Time.parse(u['deletedAt'])
        (now - del) > (7*24*60*60)
      rescue
        false
      end
    else
      false
    end
  end
  write_users(pruned) if pruned.length != users.length
  res.body = { users: pruned.map { |u| sanitize_user(u) } }.to_json
end

# Admin: delete user (soft)
server.mount_proc '/api/admin/delete' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  id = body['id']
  user = users.find { |u| u['__backendId'] == id }
  unless user
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  user['deleted'] = true
  user['deletedAt'] = Time.now.iso8601
  write_users(users)
  res.body = { ok: true }.to_json
end

# Admin: restore user
server.mount_proc '/api/admin/restore' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  id = body['id']
  user = users.find { |u| u['__backendId'] == id }
  unless user
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  user['deleted'] = false
  user['deletedAt'] = nil
  write_users(users)
  res.body = { ok: true }.to_json
end

# Admin: approve payment
server.mount_proc '/api/admin/approve' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  id = body['id']
  slot = body['slot']
  user = users.find { |u| u['__backendId'] == id }
  unless user
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  profile = user['data'] ? JSON.parse(user['data']) : {}
  profile['paymentApproved'] = true
  cards = profile['cards'] || []
  card = cards.find { |c| c['slot'] == slot }
  if card
    card['ordered'] = true
    card['status'] = 'active'
  end
  profile['cards'] = cards
  user['data'] = JSON.dump(profile)
  write_users(users)
  res.body = { ok: true, user: sanitize_user(user) }.to_json
end

# Admin: delete a user's card slot (reset order)
server.mount_proc '/api/admin/delete_card' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  user_id = body['user_id']
  slot = body['slot']
  user = users.find { |u| u['__backendId'] == user_id }
  unless user
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  profile = user['data'] ? JSON.parse(user['data']) : {}
  cards = profile['cards'] || []
  cards = cards.reject { |c| c['slot'] == slot }
  profile['cards'] = cards
  user['data'] = JSON.dump(profile)
  write_users(users)
  res.body = { ok: true }.to_json
end

# Admin: approve user profile (e.g., sub-admin confirmation)
server.mount_proc '/api/admin/approve_profile' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  user_id = body['user_id']
  user = users.find { |u| u['__backendId'] == user_id }
  unless user
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  profile = user['data'] ? JSON.parse(user['data']) : {}
  profile['profileApproved'] = true
  user['data'] = JSON.dump(profile)
  write_users(users)
  res.body = { ok: true }.to_json
end

# Admin: create/update a user's card slot
server.mount_proc '/api/admin/create_card' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  user_id = body['user_id']
  slot = body['slot']
  design = body['design']
  name_text = body['nameText']
  phone_text = body['phoneText']
  qr_type = body['qrType']
  qr_text = body['qrText']
  show_phone = !!body['showPhoneOnCard']
  design_image = body['designImage']
  user = users.find { |u| u['__backendId'] == user_id }
  unless user
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  profile = user['data'] ? JSON.parse(user['data']) : {}
  cards = profile['cards'] || []
  cards = cards.reject { |c| c['slot'] == slot }
  new_card = {
    'slot' => slot,
    'design' => design,
    'nameText' => name_text,
    'phoneText' => phone_text,
    'qrType' => qr_type,
    'qrText' => qr_text,
    'showPhoneOnCard' => show_phone,
    'designImage' => design_image,
    'createdAt' => Time.now.iso8601
  }
  cards << new_card
  profile['cards'] = cards
  user['data'] = JSON.dump(profile)
  write_users(users)
  res.body = { ok: true }.to_json
end
# Admin: change login email
server.mount_proc '/api/admin/email' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  id = body['id']
  new_email = body['email']&.strip
  if !new_email || new_email.empty?
    res.status = 400; res.body = { error: 'invalid' }.to_json; next
  end
  if users.any? { |u| u['email'].to_s.downcase == new_email.downcase && u['__backendId'] != id }
    res.status = 409; res.body = { error: 'exists' }.to_json; next
  end
  user = users.find { |u| u['__backendId'] == id }
  unless user
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  user['email'] = new_email
  write_users(users)
  res.body = { ok: true, user: sanitize_user(user) }.to_json
end
# Admin: reset user password
server.mount_proc '/api/admin/reset_password' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  id = body['id']
  new_pwd = body['password'].to_s
  unless valid_password?(new_pwd)
    res.status = 400; res.body = { error: 'weak_password' }.to_json; next
  end
  user = users.find { |u| u['__backendId'] == id }
  unless user
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  nh = hash_password(new_pwd)
  user['passwordSalt'] = nh['salt']
  user['passwordHash'] = nh['hash']
  write_users(users)
  res.body = { ok: true, user: sanitize_user(user) }.to_json
end
# Admin: register sub-admin
server.mount_proc '/api/admin/register_subadmin' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  name = body['name']
  email = body['email']
  username = body['username']
  password = body['password']
  phone = body['phone'] || ''
  if [name,email,username,password].any? { |v| v.to_s.strip.empty? }
    res.status = 400; res.body = { error: 'invalid' }.to_json; next
  end
  if users.any? { |u| u['email'].to_s.downcase == email.to_s.downcase || u['username'].to_s.downcase == username.to_s.downcase }
    res.status = 409; res.body = { error: 'exists' }.to_json; next
  end
  unless valid_password?(password)
    res.status = 400; res.body = { error: 'weak_password' }.to_json; next
  end
  profile = { jobTitle: '', company: '', about: '', created: Time.now.iso8601, cards: [] }
  subadmin = create_user_object({ name: name, email: email, username: username, phone: phone, password: password, is_admin: false, data: profile })
  subadmin['is_subadmin'] = true
  users << subadmin
  write_users(users)
  res.body = { ok: true }.to_json
end
trap('INT') { server.shutdown }
server.start
