require 'webrick'
require 'json'
require 'securerandom'
require 'openssl'

PORT = 5050
ALLOWED_ORIGINS = ['http://localhost:8000','http://127.0.0.1:8000']
DATA_DIR = File.join(__dir__, 'data')
USERS_FILE = File.join(DATA_DIR, 'users.json')

SESSIONS = {}

def ensure_data
  Dir.mkdir(DATA_DIR) unless Dir.exist?(DATA_DIR)
  unless File.exist?(USERS_FILE)
    admin = create_user_object({
      name: 'Administrator',
      email: 'admin@a',
      username: 'systemadmin',
      phone: '+60 12-000 0000',
      password: '123',
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
server.mount('/DuoBuddy.html', WEBrick::HTTPServlet::FileHandler, Dir.pwd)
server.mount_proc '/' do |req, res|
  if req.path == '/' || req.path.empty?
    res.status = 302
    res['Location'] = '/DuoBuddy.html'
  else
    # For any other static path, attempt to read and serve the file
    path = File.join(Dir.pwd, req.path)
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
  body = parse_body(req)
  email,password = body.values_at('email','password')
  users = read_users
  user = users.find { |u| u['email'] == email }
  unless user
    res.status = 401; res.body = { error: 'invalid' }.to_json; next
  end
  hp = hash_password(password, user['passwordSalt'])
  if hp['hash'] != user['passwordHash']
    res.status = 401; res.body = { error: 'invalid' }.to_json; next
  end
  sid = SecureRandom.hex(16)
  SESSIONS[sid] = user['__backendId']
  res['Set-Cookie'] = "sid=#{sid}; HttpOnly; Path=/; SameSite=Lax"
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
  res['Set-Cookie'] = "sid=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax"
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
  slot,design,quantity,address,notes,paymentProof = body.values_at('slot','design','quantity','address','notes','paymentProof')
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
  else
    cards << { 'slot' => slot, 'ordered' => false, 'design' => design, 'quantity' => quantity, 'orderDate' => now, 'paymentProof' => paymentProof, 'address' => address, 'notes' => notes, 'status' => 'pending_approval' }
  end
  profile['cards'] = cards
  user['data'] = JSON.dump(profile)
  write_users(users)
  res.body = { user: sanitize_user(user) }.to_json
end

trap('INT') { server.shutdown }
server.start
