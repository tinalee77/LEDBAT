/*
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the 
 * Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
 *
 * Created by Silvio Valenti on tue 2nd June 2009
 * 
 * Updated to conform to RFC6817 by Qian Li
 * 
 */

#include <linux/module.h>
#include <net/tcp.h>
#include <linux/vmalloc.h>

// working environment for ledbat, 0 -- emulator, 1 -- internet
static int env = 0;
module_param(env, int, 0644);
MODULE_PARM_DESC(env, "working environment");

static int hz = 0;
module_param(hz, int, 0644);
MODULE_PARM_DESC(hz, "HZ of remote internet host");

static int do_ss = 1;
module_param(do_ss, int, 0644);
MODULE_PARM_DESC(do_ss, "if do slow start");

static int min_cwnd = 2;
module_param(min_cwnd, int, 0644);
MODULE_PARM_DESC(min_cwnd, "min cwnd");

/* NOTE: len are the array length - 1 */
static int base_histo_len = 10;
module_param(base_histo_len, int, 0644);
MODULE_PARM_DESC(base_histo_len, "length of the base history vector");

/* NOTE: len are the array length - 1 */
static int noise_filter_len = 1;
module_param(noise_filter_len, int, 0644);
MODULE_PARM_DESC(noise_filter_len, "length of the noise_filter vector");

static int target = 100;
module_param(target, int, 0644);
MODULE_PARM_DESC(target, "target queuing delay");

static int gain_inc = 1;
module_param(gain_inc, int, 0644);
MODULE_PARM_DESC(gain_inc, "increase gain");

static int gain_dec = 1;
module_param(gain_dec, int, 0644);
MODULE_PARM_DESC(gain_dec, "decrease gain");


/*
 * TCP-LEDBAT's state flags.
 */
enum tcp_ledbat_state {
	LEDBAT_VALID_RHZ = (1 << 0),
	LEDBAT_CAN_SS = (1 << 1)
};

struct owd_circ_buf {
	s64 *buffer;
	u8 first;
	u8 next;
	u8 len;
	u8 min;
};

/**
 * struct ledbat
 */
struct ledbat {
	struct owd_circ_buf base_history;
	struct owd_circ_buf noise_filter;
	s64 byte_cnt;
	u32 last_rollover;
	u32 remote_hz;
	u32 remote_ref_time;
	u32 local_ref_time;
	u32 flag;
};

static int ledbat_init_circbuf(struct owd_circ_buf *buffer, u16 len)
{
	s64 *b = kmalloc(len * sizeof(s64), GFP_KERNEL);
	if (b == NULL)
		return 1;
	buffer->len = len;
	buffer->buffer = b;
	buffer->first = 0;
	buffer->next = 0;
	buffer->min = 0;
	return 0;
}

static void tcp_ledbat_release(struct sock *sk)
{
	struct ledbat *ledbat = inet_csk_ca(sk);
	
	kfree(ledbat->noise_filter.buffer);
	kfree(ledbat->base_history.buffer);
}

/**
 * tcp_ledbat_init
 */
static void tcp_ledbat_init(struct sock *sk)
{
	struct ledbat *ledbat = inet_csk_ca(sk);

	ledbat_init_circbuf(&(ledbat->base_history), base_histo_len + 1);
	ledbat_init_circbuf(&(ledbat->noise_filter), noise_filter_len + 1);

	ledbat->byte_cnt = 0;
	ledbat->last_rollover = 0;
	ledbat->flag = LEDBAT_CAN_SS;
	ledbat->remote_hz = 0;
	ledbat->remote_ref_time = 0;
	ledbat->local_ref_time = 0;
}

typedef s64 (*ledbat_filter_function) (struct owd_circ_buf *);

static s64 ledbat_min_circ_buff(struct owd_circ_buf *b)
{
	/* 
	   The draft requires all history to be set to +infinity on initialization. 
	   We obtain the same behavior returning +infinity in case of empty history.
	 */
	if (b->first == b->next)
		return (~0LLU) >> 1;
	return b->buffer[b->min];
}

static s64 ledbat_current_delay(struct ledbat *ledbat, ledbat_filter_function filter)
{
	return filter(&(ledbat->noise_filter));
}

static s64 ledbat_base_delay(struct ledbat *ledbat)
{
	return ledbat_min_circ_buff(&(ledbat->base_history));
}

static u32 tcp_ledbat_ssthresh(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	u32 res;
	
	res = tcp_reno_ssthresh(sk);
	
	return res;
}

static void tcp_ledbat_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ledbat *ledbat = inet_csk_ca(sk);

	switch (ev) {
	case CA_EVENT_CWND_RESTART: // after idle, cwnd is restarted
		ledbat->flag |= LEDBAT_CAN_SS;
		ledbat->byte_cnt = 0;
		break;
	case CA_EVENT_COMPLETE_CWR: // after fast retransmit and fast recovery
		ledbat->flag &= ~LEDBAT_CAN_SS;
		ledbat->byte_cnt = 0;
		break;
	case CA_EVENT_LOSS: // rto timer timeout
		ledbat->flag |= LEDBAT_CAN_SS;
		ledbat->byte_cnt = 0;
		break;
	default:
		break;
	}
}

static bool is_cwnd_limited(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ledbat *ledbat = inet_csk_ca(sk);

	if (do_ss && (ledbat->flag & LEDBAT_CAN_SS) && tp->snd_cwnd < tp->snd_ssthresh)
		return tp->snd_cwnd < 2 * tp->max_packets_out;

	return tp->is_cwnd_limited;
}

/**
 * tcp_ledbat_cong_avoid
 */
static void tcp_ledbat_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct ledbat *ledbat = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	s64 current_delay, base_delay, queue_delay, off_target, gain, cwnd, adj_b, adj_p;
	u64 max_allowed_cwnd = 0;
	
	/*if no valid data return */
	if (!(ledbat->flag & LEDBAT_VALID_RHZ)) {
		return;
	}

	if (do_ss && tp->snd_cwnd < tp->snd_ssthresh && (ledbat->flag & LEDBAT_CAN_SS)) {
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	} 

	current_delay = ledbat_current_delay(ledbat, &ledbat_min_circ_buff);
	base_delay = ledbat_base_delay(ledbat);
	queue_delay = current_delay - base_delay;
	off_target = target - queue_delay;
	if (off_target >= 0) {
		if (!is_cwnd_limited(sk)) {
			//ledbat->byte_cnt = 0;
			return;
		}
		gain = gain_inc;
	} else {
		gain = gain_dec;
	}
	ledbat->byte_cnt += off_target * gain * acked * tp->mss_cache;
	if (tp->snd_cwnd && target)
		adj_b = div_s64(ledbat->byte_cnt, tp->snd_cwnd * target);
	if (tp->mss_cache)
		adj_p = div_s64(adj_b, tp->mss_cache);
	if (adj_p) {
		ledbat->byte_cnt -= adj_b * tp->snd_cwnd * target;
		max_allowed_cwnd = min_t(u64, (u64)tp->snd_cwnd + 1, tp->snd_cwnd_clamp);
		cwnd = tp->snd_cwnd + adj_p;
		cwnd = min_t(s64, cwnd, max_allowed_cwnd);
		cwnd = max_t(s64, cwnd, min_cwnd);
		tp->snd_cwnd = cwnd;
	}
}

/**
 * tcp_ledbat_remote_hz_estimator
 *
 * Estimate remote HZ.
 * We keep on updating the estimated value, where original TCP-LP
 * implementation only guesses it once and uses it forever.
 */
static void tcp_ledbat_remote_hz_estimator(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ledbat *ledbat = inet_csk_ca(sk);
	u32 rhz = ledbat->remote_hz << 6;	
	s32 m;
	
	if (!env) { // working environment is emulator
		rhz = TCP_TS_HZ << 6;
		goto out;
	}
	
	if (env && hz) { // internet but remote hz is known
		rhz = hz << 6;
		goto out;
	}
	
	// working environment is internet

	/* not yet record reference time
	 * go away!! record it before come back!! */
	if (ledbat->remote_ref_time == 0 || ledbat->local_ref_time == 0)
		goto out;

	/* we can't calc remote HZ with no difference!! */
	if (tp->rx_opt.rcv_tsval <= ledbat->remote_ref_time || tp->rx_opt.rcv_tsecr <= ledbat->local_ref_time)
		goto out;

	// m > 0
	m = TCP_TS_HZ * (tp->rx_opt.rcv_tsval - ledbat->remote_ref_time) / (tp->rx_opt.rcv_tsecr - ledbat->local_ref_time);

	if (rhz) {
		m -= rhz >> 6;	/* m is now error in remote HZ est */
		rhz += m;	/* 63/64 old + 1/64 new */
	} else
		rhz = m << 6;

	out:
	ledbat->remote_hz = rhz >> 6;

	/* record time for successful remote HZ calc, rhz > 0 for sure */
	if (ledbat->remote_hz)
		ledbat->flag |= LEDBAT_VALID_RHZ;
	else
		ledbat->flag &= ~LEDBAT_VALID_RHZ;

	/* record reference time stamp */
	ledbat->remote_ref_time = tp->rx_opt.rcv_tsval;
	ledbat->local_ref_time = tp->rx_opt.rcv_tsecr;
}

/**
 * tcp_ledbat_owd_calculator
 */
static s64 tcp_ledbat_owd_calculator(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ledbat *ledbat = inet_csk_ca(sk);
	struct inet_sock *inet = inet_sk(sk);
	s64 owd = 0;
	
	tcp_ledbat_remote_hz_estimator(sk);

	if (ledbat->flag & LEDBAT_VALID_RHZ) {
		owd = tp->rx_opt.rcv_tsval * (MSEC_PER_SEC / ledbat->remote_hz) - tp->rx_opt.rcv_tsecr * (MSEC_PER_SEC / TCP_TS_HZ);
	} 
	 
	return owd;
}

static void ledbat_add_delay(struct owd_circ_buf *cb, s64 owd)
{
	u8 i;

	if (cb->next == cb->first) {
		/*buffer is empty */
		cb->buffer[cb->next] = owd;
		cb->min = cb->next;
		cb->next++;
		return;
	}

	/*set the new delay */
	cb->buffer[cb->next] = owd;
	/* update the min if it is the case */
	if (owd < cb->buffer[cb->min])
		cb->min = cb->next;

	/* increment the next pointer */
	cb->next = (cb->next + 1) % cb->len;

	if (cb->next == cb->first) {
		/* Discard the first element */
		if (cb->min == cb->first) {
			/* Discard the min, search a new one */
			cb->min = i = (cb->first + 1) % cb->len;
			while (i != cb->next) {
				if (cb->buffer[i] < cb->buffer[cb->min])
					cb->min = i;
				i = (i + 1) % cb->len;
			}
		}
		/* move the first */
		cb->first = (cb->first + 1) % cb->len;
	}
}

static void ledbat_update_current_delay(struct ledbat *ledbat, s64 owd)
{
	ledbat_add_delay(&(ledbat->noise_filter), owd);
}

static void ledbat_update_base_delay(struct ledbat *ledbat, s64 owd)
{
	u32 last;
	struct owd_circ_buf *cb = &(ledbat->base_history);
	

	if (ledbat->last_rollover == 0)
		ledbat->last_rollover = tcp_jiffies32;

	if (ledbat->base_history.next == ledbat->base_history.first) {
		/* empty circular buffer */
		ledbat_add_delay(cb, owd);
		return;
	}

	if (tcp_jiffies32 - ledbat->last_rollover > msecs_to_jiffies(60 * MSEC_PER_SEC)) {
		/* we have finished a minute */
		ledbat->last_rollover = tcp_jiffies32;
		ledbat_add_delay(cb, owd);
	} else {
		/* update the last value and the min if it is the case */
		last = (cb->next + cb->len - 1) % cb->len;
		if (owd < cb->buffer[last]) {
			cb->buffer[last] = owd;
			if (owd < cb->buffer[cb->min])
				cb->min = last;
		}
	}
}

/**
 * tcp_ledbat_rtt_sample
 *
 * - calculate the owd
 * - add the delay to noise filter
 * - if new minute add the delay to base delay or update last delay 
 */
static void tcp_ledbat_rtt_sample(struct sock *sk, u32 rtt)
{
	struct ledbat *ledbat = inet_csk_ca(sk);
	s64 mowd = tcp_ledbat_owd_calculator(sk);

	/* sorry that we don't have valid data */
	if (!(ledbat->flag & LEDBAT_VALID_RHZ)) {
		return;
	}

	ledbat_update_current_delay(ledbat, mowd);
	ledbat_update_base_delay(ledbat, mowd);
}

/**
 * tcp_ledbat_pkts_acked
 */
static void tcp_ledbat_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct inet_sock *inet = inet_sk(sk);
	
	if (sk->sk_state == TCP_SYN_SENT || sk->sk_state == TCP_SYN_RECV || sk->sk_state == TCP_NEW_SYN_RECV || sk->sk_state == TCP_LISTEN) {
		return;
	}

	if (sample->rtt_us > 0)
		tcp_ledbat_rtt_sample(sk, sample->rtt_us);
}

/**
 * tcp_ledbat_undo_cwnd
 * required starting kernel v4.10, see
 * kernel commmit e97991832a4ea4a5f47d65f068a4c966a2eb5730
 */
static u32 tcp_ledbat_undo_cwnd(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	
	return max(tp->snd_cwnd, tp->snd_ssthresh << 1);
}

static struct tcp_congestion_ops tcp_ledbat = {
	.init = tcp_ledbat_init,
	.ssthresh = tcp_ledbat_ssthresh,
	.cong_avoid = tcp_ledbat_cong_avoid,
	.pkts_acked = tcp_ledbat_pkts_acked,
	.undo_cwnd = tcp_ledbat_undo_cwnd,
	.cwnd_event = tcp_ledbat_cwnd_event,
	.release = tcp_ledbat_release,

	.owner = THIS_MODULE,
	.name = "ledbat"
};

static int __init tcp_ledbat_register(void)
{
	BUILD_BUG_ON(sizeof(struct ledbat) > ICSK_CA_PRIV_SIZE);
	
	return tcp_register_congestion_control(&tcp_ledbat);
}

static void __exit tcp_ledbat_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_ledbat);
}

module_init(tcp_ledbat_register);
module_exit(tcp_ledbat_unregister);

MODULE_AUTHOR("Silvio Valenti and Qian Li");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP Ledbat (Low Extra Delay Background Transport)");
