document.addEventListener('DOMContentLoaded', () => {

  // ==========================================
  // 1. AUTHENTICATION (LOGIN / REGISTER) LOGIC
  // ==========================================
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
      const tabs = document.getElementById('tabs');
      const tabLogin = document.getElementById('tabLogin');
      const tabRegister = document.getElementById('tabRegister');
      const registerForm = document.getElementById('registerForm');
      const loginHint = document.getElementById('loginHint');
      const registerHint = document.getElementById('registerHint');

      function showLogin(){
        tabs.classList.remove('register');
        tabLogin.classList.add('active');
        tabRegister.classList.remove('active');
        loginForm.classList.remove('hidden');
        registerForm.classList.add('hidden');
        loginHint.classList.remove('hidden');
        registerHint.classList.add('hidden');
      }

      function showRegister(){
        tabs.classList.add('register');
        tabRegister.classList.add('active');
        tabLogin.classList.remove('active');
        registerForm.classList.remove('hidden');
        loginForm.classList.add('hidden');
        registerHint.classList.remove('hidden');
        loginHint.classList.add('hidden');
      }

      tabLogin.addEventListener('click', showLogin);
      tabRegister.addEventListener('click', showRegister);
      document.getElementById('goRegister')?.addEventListener('click', showRegister);
      document.getElementById('goLogin')?.addEventListener('click', showLogin);

      function setMsg(el, text){
        el.textContent = text;
        el.classList.add('show');
      }
      function clearMsgs(...els){
        els.forEach(el => { el.classList.remove('show'); el.textContent = ''; });
      }
      function setLoading(btn, isLoading){
        btn.disabled = isLoading;
        btn.classList.toggle('loading', isLoading);
      }

      const loginError = document.getElementById('loginError');
      const loginSuccess = document.getElementById('loginSuccess');
      const loginBtn = document.getElementById('loginBtn');

      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        clearMsgs(loginError, loginSuccess);
        const username = document.getElementById('loginUsername').value.trim();
        const password = document.getElementById('loginPassword').value;

        setLoading(loginBtn, true);
        try {
          const res = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
          });
          const data = await res.json();
          if (data.success) {
            setMsg(loginSuccess, data.message || 'Login successful!');
            setTimeout(() => { window.location.href = '/dashboard'; }, 500);
          } else {
            setMsg(loginError, data.message || 'Invalid username or password.');
          }
        } catch (err) {
          setMsg(loginError, 'Could not reach the server. Please try again.');
        } finally {
          setLoading(loginBtn, false);
        }
      });

      const registerError = document.getElementById('registerError');
      const registerSuccess = document.getElementById('registerSuccess');
      const registerBtn = document.getElementById('registerBtn');

      registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        clearMsgs(registerError, registerSuccess);
        const username = document.getElementById('regUsername').value.trim();
        const password = document.getElementById('regPassword').value;
        const confirm = document.getElementById('regConfirm').value;

        if (password !== confirm) {
          setMsg(registerError, 'Passwords do not match.');
          return;
        }

        setLoading(registerBtn, true);
        try {
          const res = await fetch('/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
          });
          const data = await res.json();
          if (data.success) {
            setMsg(registerSuccess, data.message || 'Registration successful!');
            registerForm.reset();
            setTimeout(showLogin, 900);
          } else {
            setMsg(registerError, data.message || 'Registration failed.');
          }
        } catch (err) {
          setMsg(registerError, 'Server error.');
        } finally {
          setLoading(registerBtn, false);
        }
      });
  }

  // ==========================================
  // 2. DASHBOARD & SOCKET.IO LOGIC
  // ==========================================
  const canvasEl = document.getElementById('liveChart');
  if (canvasEl) {
      const ctx = canvasEl.getContext('2d');
      const MAX_POINTS = 30;
      const labels = Array(MAX_POINTS).fill('');
      const trafficData = Array(MAX_POINTS).fill(0);
      const threatData = Array(MAX_POINTS).fill(0);

      const gradTraffic = ctx.createLinearGradient(0, 0, 0, 230);
      gradTraffic.addColorStop(0, 'rgba(59,130,246,0.35)');
      gradTraffic.addColorStop(1, 'rgba(59,130,246,0)');

      const gradThreat = ctx.createLinearGradient(0, 0, 0, 230);
      gradThreat.addColorStop(0, 'rgba(244,63,94,0.35)');
      gradThreat.addColorStop(1, 'rgba(244,63,94,0)');

      window.chart = new Chart(ctx, {
        type: 'line',
        data: {
          labels,
          datasets: [
            { label: 'Network Traffic', data: trafficData, borderColor: '#3b82f6', backgroundColor: gradTraffic, fill: true, tension: 0.4, pointRadius: 0, borderWidth: 2 },
            { label: 'Threat Level', data: threatData, borderColor: '#f43f5e', backgroundColor: gradThreat, fill: true, tension: 0.4, pointRadius: 0, borderWidth: 2 }
          ]
        },
        options: {
          responsive: true, maintainAspectRatio: false, animation: { duration: 400 }, plugins: { legend: { display: false } },
          scales: { x: { display: false }, y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#7b8494', font: { size: 10 } } } }
        }
      });

      function pushPoint(arr, value) {
        arr.push(value);
        if (arr.length > MAX_POINTS) arr.shift();
      }

      window.switchView = function(view) {
        const btnDashboard = document.getElementById('nav-dashboard');
        const btnLiveTraffic = document.getElementById('nav-livetraffic');
        const statsSection = document.getElementById('stats-section');
        const tableSection = document.getElementById('table-section');
        const chartWrap = document.getElementById('chart-wrap-container');

        if (view === 'livetraffic') {
            btnDashboard.classList.remove('active');
            btnLiveTraffic.classList.add('active');
            statsSection.style.display = 'none';
            tableSection.style.display = 'none';
            chartWrap.style.height = 'calc(100vh - 200px)';
            window.chart.options.scales.x.display = true;
        } else if (view === 'dashboard') {
            btnLiveTraffic.classList.remove('active');
            btnDashboard.classList.add('active');
            statsSection.style.display = '';
            tableSection.style.display = '';
            chartWrap.style.height = '230px';
            window.chart.options.scales.x.display = false;
        }
        window.chart.resize();
        window.chart.update('none');
      };

      const statBlocked = document.getElementById('statBlocked');
      const statAnomalies = document.getElementById('statAnomalies');
      const statRuleMatches = document.getElementById('statRuleMatches');
      const alertsCount = document.getElementById('alertsCount');
      const threatBody = document.getElementById('threatBody');
      const sysStatus = document.getElementById('sys-status');
      let alerts = 0;

      function flashCard(id) {
        const el = document.getElementById(id);
        if(el){ el.classList.remove('flash'); void el.offsetWidth; el.classList.add('flash'); }
      }

      function bumpAlerts() {
        if(!alertsCount) return;
        alerts += 1; alertsCount.textContent = alerts; alertsCount.classList.remove('bump');
        void alertsCount.offsetWidth; alertsCount.classList.add('bump');
        setTimeout(() => alertsCount.classList.remove('bump'), 250);
      }

      function addThreatRow({ time, ip, label, simulated, ruleMatched, dlProbability, riskScore }) {
        if(!threatBody) return;
        const tr = document.createElement('tr');
        const ruleBadge = ruleMatched
          ? `<span class="rule-badge">FP-Growth match</span>`
          : '';
        tr.innerHTML = `
          <td>${time}${simulated ? '<span class="sim-tag">TEST</span>' : ''}</td>
          <td>${ip || 'N/A'}</td>
          <td><span class="badge alert">Attack Detected</span> ${ruleBadge}</td>
          <td class="action-blocked">[Blocked]</td>
        `;
        threatBody.prepend(tr);
        if (threatBody.rows.length > 12) threatBody.deleteRow(12);
      }

      // ---------------------------------------
      // ATTACK START/STOP BUTTON
      // ---------------------------------------
      const attackToggleBtn = document.getElementById('attackToggleBtn');
      const attackToggleText = document.getElementById('attackToggleText');

      function renderAttackButton(active) {
        if (!attackToggleBtn) return;
        attackToggleBtn.classList.toggle('active', active);
        if (attackToggleText) {
          attackToggleText.textContent = active ? 'Stop Attack' : 'Start Attack';
        }
      }

      if (attackToggleBtn) {
        fetch('/attack_status')
          .then(res => res.json())
          .then(data => renderAttackButton(!!data.active))
          .catch(() => {});

        attackToggleBtn.addEventListener('click', async () => {
          attackToggleBtn.disabled = true;
          try {
            const res = await fetch('/toggle_attack', { method: 'POST' });
            const data = await res.json();
            renderAttackButton(!!data.active);
          } catch (err) {
            console.error('Attack toggle failed:', err);
          } finally {
            attackToggleBtn.disabled = false;
          }
        });
      }

      // ---------------------------------------
      // THREAT LEVEL (red line) — smooth scrolling state
      // ---------------------------------------
      let currentThreatLevel = 0;
      const THREAT_DECAY = 0.82;

      // SOCKET.IO CONNECTION
      const socket = io();

      socket.on('normal_traffic', (data) => {
        pushPoint(trafficData, data.chart_value);
        pushPoint(threatData, currentThreatLevel);
        currentThreatLevel *= THREAT_DECAY;
        if (currentThreatLevel < 1) currentThreatLevel = 0;

        let timeNow = new Date().toLocaleTimeString();
        labels.shift(); labels.push(timeNow);
        window.chart.update('none');

        if (sysStatus && sysStatus.innerText.includes('THREAT')) {
            sysStatus.innerHTML = '<span class="status-dot" style="background:#22c55e;"></span>System Online (Safe)';
            sysStatus.style.color = 'var(--text)';
        }
      });

      socket.on('attack_prediction', function(data) {
        // 'probability' ab Risk Engine ka FINAL combined score hai
        // (DL model + FP-Growth rule match ka weighted combine)
        currentThreatLevel = data.probability || 80;

        if(statBlocked) statBlocked.innerText = data.attacks_blocked || 0;
        if(statAnomalies) statAnomalies.innerText = data.anomalies || 0;
        if(statRuleMatches) statRuleMatches.innerText = data.rule_matches || 0;

        flashCard('cardBlocked'); flashCard('cardAnomalies');
        if (data.rule_matched) flashCard('cardRuleMatches');
        bumpAlerts();

        if (sysStatus) {
            sysStatus.innerHTML = '⚠️ THREAT DETECTED';
            sysStatus.style.color = '#FF1744';
        }

        addThreatRow({
          time: data.time || new Date().toLocaleTimeString(),
          ip: data.ip,
          label: data.label,
          simulated: data.simulated,
          ruleMatched: data.rule_matched,
          dlProbability: data.dl_probability,
          riskScore: data.probability
        });
      });
  }
});