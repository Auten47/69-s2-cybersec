'use strict';

const net = require('net');

const fold = (str) =>
  Buffer.from(str, 'utf-8')
    .toString('base64')
    .replace(/(.{76})/g, '$1\r\n')
    .replace(/\r\n$/, '');

const buildMessage = ({ from, to, cc, bcc, replyTo, subject, text, html }) => {
  const toList = [].concat(to || []).filter(Boolean).join(', ');
  const boundary = 'strapiMail-' + Date.now().toString(36);

  const bodyParts = [];
  if (html && text) {
    bodyParts.push(`--${boundary}\r\nContent-Type: text/plain; charset="UTF-8"\r\nContent-Transfer-Encoding: base64\r\n\r\n${fold(text)}\r\n`);
    bodyParts.push(`--${boundary}\r\nContent-Type: text/html; charset="UTF-8"\r\nContent-Transfer-Encoding: base64\r\n\r\n${fold(html)}\r\n`);
    bodyParts.push(`--${boundary}--`);
  } else {
    const contentType = html ? 'text/html' : 'text/plain';
    bodyParts.push(`Content-Type: ${contentType}; charset="UTF-8"\r\nContent-Transfer-Encoding: base64\r\n\r\n${fold(html || text || '')}`);
  }

  const headers = [
    `From: ${from}`,
    `To: ${toList}`,
    replyTo ? `Reply-To: ${replyTo}` : null,
    `Subject: ${subject}`,
    html && text
      ? `MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary="${boundary}"`
      : 'MIME-Version: 1.0',
  ].filter(Boolean);

  return [...headers, '', ...bodyParts, ''].join('\r\n');
};

const smtpSend = ({ host, port, from, recipients, message }) =>
  new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });

    let buffer = '';
    let waiting = [];

    const onData = (chunk) => {
      buffer += chunk.toString('utf-8');
      let idx;
      while ((idx = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, idx).replace(/\r$/, '');
        buffer = buffer.slice(idx + 1);
        if (/^\d{3}[- ]/.test(line) && line[3] === ' ') {
          const waiter = waiting.shift();
          if (waiter) waiter(parseInt(line.slice(0, 3), 10));
        }
      }
    };

    const onError = (err) => {
      waiting = [];
      reject(err);
    };

    socket.on('data', onData);
    socket.on('error', onError);
    socket.setTimeout(15000, () => {
      socket.destroy();
      onError(new Error('SMTP timeout'));
    });

    const reply = () => new Promise((res) => waiting.push(res));

    const command = async (line) => {
      socket.write(line + '\r\n');
      const code = await reply();
      if (code >= 400) throw new Error(`SMTP "${line.split(' ')[0]}" rejected with ${code}`);
    };

    (async () => {
      const greeting = await reply();
      if (greeting >= 400) throw new Error(`SMTP greeting rejected with ${greeting}`);

      await command('EHLO localhost');
      await command(`MAIL FROM:<${from}>`);
      for (const rcpt of recipients) {
        await command(`RCPT TO:<${rcpt}>`);
      }
      await command('DATA');
      socket.write(message + '\r\n.\r\n');
      const queued = await reply();
      if (queued >= 400) throw new Error(`SMTP DATA rejected with ${queued}`);
      await command('QUIT');

      socket.end();
      resolve({ messageId: `mailhog-${Date.now()}` });
    })().catch(onError);
  });

module.exports = {
  provider: 'smtp',
  name: 'SMTP (MailHog compatible)',
  init(providerOptions = {}, settings = {}) {
    const host = providerOptions.host || 'mailhog';
    const port = providerOptions.port || 1025;
    const defaultFrom =
      settings.defaultFrom || providerOptions.defaultFrom || 'no-reply@authen.local';

    return {
      send(options) {
        const recipients = [].concat(options.to || [], options.cc || [], options.bcc || []).filter(Boolean);
        if (recipients.length === 0) {
          return Promise.reject(new Error('No recipients specified'));
        }
        const message = buildMessage({
          from: options.from || defaultFrom,
          to: options.to,
          cc: options.cc,
          bcc: options.bcc,
          replyTo: options.replyTo,
          subject: options.subject,
          text: options.text,
          html: options.html,
        });
        return smtpSend({ host, port, from: options.from || defaultFrom, recipients, message });
      },
    };
  },
};