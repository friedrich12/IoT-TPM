#include "Enclave_t.h"

#include "sgx_trts.h"	/* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h>		/* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz)                          \
	do {                                                     \
		if (!(ptr) || !sgx_is_outside_enclave((ptr), (siz))) \
			return SGX_ERROR_INVALID_PARAMETER;              \
	} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz)                      \
	do {                                                    \
		if ((ptr) && !sgx_is_outside_enclave((ptr), (siz))) \
			return SGX_ERROR_INVALID_PARAMETER;             \
	} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz)                    \
	do {                                                   \
		if ((ptr) && !sgx_is_within_enclave((ptr), (siz))) \
			return SGX_ERROR_INVALID_PARAMETER;            \
	} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) ( \
	((a) += (b)) < (b))


typedef struct ms_ecall_start_tls_client_t {
	const char * ms_inter;
	size_t		 ms_inter_len;
	const char * ms_priv;
	size_t		 ms_priv_len;
	const char * ms_iot_ip;
	size_t		 ms_iot_ip_len;
	const char * ms_serverip;
	size_t		 ms_serverip_len;
	char *		 ms_filedata;
	size_t		 ms_filedata_len;
} ms_ecall_start_tls_client_t;

typedef struct ms_ocall_sgx_clock_t {
	long int ms_retval;
} ms_ocall_sgx_clock_t;

typedef struct ms_ocall_sgx_time_t {
	time_t	 ms_retval;
	time_t * ms_timep;
	int		 ms_t_len;
} ms_ocall_sgx_time_t;

typedef struct ms_ocall_sgx_localtime_t {
	struct tm *	   ms_retval;
	const time_t * ms_timep;
	int			   ms_t_len;
} ms_ocall_sgx_localtime_t;

typedef struct ms_ocall_sgx_gmtime_r_t {
	struct tm *	   ms_retval;
	const time_t * ms_timep;
	int			   ms_t_len;
	struct tm *	   ms_tmp;
	int			   ms_tmp_len;
} ms_ocall_sgx_gmtime_r_t;

typedef struct ms_ocall_sgx_gettimeofday_t {
	int	   ms_retval;
	void * ms_tv;
	int	   ms_tv_size;
} ms_ocall_sgx_gettimeofday_t;

typedef struct ms_ocall_sgx_getsockopt_t {
	int	   ms_retval;
	int	   ms_s;
	int	   ms_level;
	int	   ms_optname;
	char * ms_optval;
	int	   ms_optval_len;
	int *  ms_optlen;
} ms_ocall_sgx_getsockopt_t;

typedef struct ms_ocall_sgx_setsockopt_t {
	int			 ms_retval;
	int			 ms_s;
	int			 ms_level;
	int			 ms_optname;
	const void * ms_optval;
	int			 ms_optlen;
} ms_ocall_sgx_setsockopt_t;

typedef struct ms_ocall_sgx_socket_t {
	int ms_retval;
	int ms_af;
	int ms_type;
	int ms_protocol;
} ms_ocall_sgx_socket_t;

typedef struct ms_ocall_sgx_listen_t {
	int ms_retval;
	int ms_s;
	int ms_backlog;
} ms_ocall_sgx_listen_t;

typedef struct ms_ocall_sgx_bind_t {
	int			 ms_retval;
	int			 ms_s;
	const void * ms_addr;
	int			 ms_addr_size;
} ms_ocall_sgx_bind_t;

typedef struct ms_ocall_sgx_connect_t {
	int			 ms_retval;
	int			 ms_s;
	const void * ms_addr;
	int			 ms_addrlen;
} ms_ocall_sgx_connect_t;

typedef struct ms_ocall_sgx_accept_t {
	int	   ms_retval;
	int	   ms_s;
	void * ms_addr;
	int	   ms_addr_size;
	int *  ms_addrlen;
} ms_ocall_sgx_accept_t;

typedef struct ms_ocall_sgx_shutdown_t {
	int ms_retval;
	int ms_fd;
	int ms_how;
} ms_ocall_sgx_shutdown_t;

typedef struct ms_ocall_sgx_read_t {
	int	   ms_retval;
	int	   ms_fd;
	void * ms_buf;
	int	   ms_n;
} ms_ocall_sgx_read_t;

typedef struct ms_ocall_sgx_write_t {
	int			 ms_retval;
	int			 ms_fd;
	const void * ms_buf;
	int			 ms_n;
} ms_ocall_sgx_write_t;

typedef struct ms_ocall_sgx_close_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_sgx_close_t;

typedef struct ms_ocall_sgx_getenv_t {
	int			 ms_retval;
	const char * ms_env;
	int			 ms_envlen;
	char *		 ms_ret_str;
	int			 ms_ret_len;
} ms_ocall_sgx_getenv_t;

typedef struct ms_ocall_print_string_t {
	const char * ms_str;
} ms_ocall_print_string_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int * ms_cpuinfo;
	int	  ms_leaf;
	int	  ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int			 ms_retval;
	const void * ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int			 ms_retval;
	const void * ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int			 ms_retval;
	const void * ms_waiter;
	const void * ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int			  ms_retval;
	const void ** ms_waiters;
	size_t		  ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL sgx_ecall_start_tls_client(void * pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_start_tls_client_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_start_tls_client_t * ms			= SGX_CAST(ms_ecall_start_tls_client_t *, pms);
	sgx_status_t				  status		= SGX_SUCCESS;
	const char *				  _tmp_inter	= ms->ms_inter;
	size_t						  _len_inter	= ms->ms_inter_len;
	char *						  _in_inter		= NULL;
	const char *				  _tmp_priv		= ms->ms_priv;
	size_t						  _len_priv		= ms->ms_priv_len;
	char *						  _in_priv		= NULL;
	const char *				  _tmp_iot_ip	= ms->ms_iot_ip;
	size_t						  _len_iot_ip	= ms->ms_iot_ip_len;
	char *						  _in_iot_ip	= NULL;
	const char *				  _tmp_serverip = ms->ms_serverip;
	size_t						  _len_serverip = ms->ms_serverip_len;
	char *						  _in_serverip	= NULL;
	char *						  _tmp_filedata = ms->ms_filedata;
	size_t						  _len_filedata = ms->ms_filedata_len;
	char *						  _in_filedata	= NULL;

	CHECK_UNIQUE_POINTER(_tmp_inter, _len_inter);
	CHECK_UNIQUE_POINTER(_tmp_priv, _len_priv);
	CHECK_UNIQUE_POINTER(_tmp_iot_ip, _len_iot_ip);
	CHECK_UNIQUE_POINTER(_tmp_serverip, _len_serverip);
	CHECK_UNIQUE_POINTER(_tmp_filedata, _len_filedata);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_inter != NULL && _len_inter != 0) {
		_in_inter = (char *)malloc(_len_inter);
		if (_in_inter == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_inter, _len_inter, _tmp_inter, _len_inter)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_inter[_len_inter - 1] = '\0';
		if (_len_inter != strlen(_in_inter) + 1) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_priv != NULL && _len_priv != 0) {
		_in_priv = (char *)malloc(_len_priv);
		if (_in_priv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_priv, _len_priv, _tmp_priv, _len_priv)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_priv[_len_priv - 1] = '\0';
		if (_len_priv != strlen(_in_priv) + 1) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_iot_ip != NULL && _len_iot_ip != 0) {
		_in_iot_ip = (char *)malloc(_len_iot_ip);
		if (_in_iot_ip == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_iot_ip, _len_iot_ip, _tmp_iot_ip, _len_iot_ip)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_iot_ip[_len_iot_ip - 1] = '\0';
		if (_len_iot_ip != strlen(_in_iot_ip) + 1) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_serverip != NULL && _len_serverip != 0) {
		_in_serverip = (char *)malloc(_len_serverip);
		if (_in_serverip == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_serverip, _len_serverip, _tmp_serverip, _len_serverip)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_serverip[_len_serverip - 1] = '\0';
		if (_len_serverip != strlen(_in_serverip) + 1) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_filedata != NULL && _len_filedata != 0) {
		_in_filedata = (char *)malloc(_len_filedata);
		if (_in_filedata == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_filedata, _len_filedata, _tmp_filedata, _len_filedata)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_filedata[_len_filedata - 1] = '\0';
		if (_len_filedata != strlen(_in_filedata) + 1) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ecall_start_tls_client((const char *)_in_inter, (const char *)_in_priv, (const char *)_in_iot_ip, (const char *)_in_serverip, _in_filedata);

err:
	if (_in_inter)
		free(_in_inter);
	if (_in_priv)
		free(_in_priv);
	if (_in_iot_ip)
		free(_in_iot_ip);
	if (_in_serverip)
		free(_in_serverip);
	if (_in_filedata)
		free(_in_filedata);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {
		void *	ecall_addr;
		uint8_t is_priv;
		uint8_t is_switchless;
	} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void *)(uintptr_t)sgx_ecall_start_tls_client, 0, 0},
	}};

SGX_EXTERNC const struct {
	size_t	nr_ocall;
	uint8_t entry_table[23][1];
} g_dyn_entry_table = {
	23,
	{
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
		{
			0,
		},
	}};


sgx_status_t SGX_CDECL ocall_sgx_clock(long int * retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_clock_t * ms			= NULL;
	size_t				   ocalloc_size = sizeof(ms_ocall_sgx_clock_t);
	void *				   __tmp		= NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_sgx_clock_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_clock_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_clock_t);

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_time(time_t * retval, time_t * timep, int t_len)
{
	sgx_status_t status		= SGX_SUCCESS;
	size_t		 _len_timep = t_len;

	ms_ocall_sgx_time_t * ms		   = NULL;
	size_t				  ocalloc_size = sizeof(ms_ocall_sgx_time_t);
	void *				  __tmp		   = NULL;

	void * __tmp_timep = NULL;

	CHECK_ENCLAVE_POINTER(timep, _len_timep);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timep != NULL) ? _len_timep : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_sgx_time_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_time_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_time_t);

	if (timep != NULL) {
		ms->ms_timep = (time_t *)__tmp;
		__tmp_timep	 = __tmp;
		memset(__tmp_timep, 0, _len_timep);
		__tmp = (void *)((size_t)__tmp + _len_timep);
		ocalloc_size -= _len_timep;
	} else {
		ms->ms_timep = NULL;
	}

	ms->ms_t_len = t_len;
	status		 = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
		if (timep) {
			if (memcpy_s((void *)timep, _len_timep, __tmp_timep, _len_timep)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_localtime(struct tm ** retval, const time_t * timep, int t_len)
{
	sgx_status_t status		= SGX_SUCCESS;
	size_t		 _len_timep = t_len;

	ms_ocall_sgx_localtime_t * ms			= NULL;
	size_t					   ocalloc_size = sizeof(ms_ocall_sgx_localtime_t);
	void *					   __tmp		= NULL;


	CHECK_ENCLAVE_POINTER(timep, _len_timep);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timep != NULL) ? _len_timep : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_sgx_localtime_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_localtime_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_localtime_t);

	if (timep != NULL) {
		ms->ms_timep = (const time_t *)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, timep, _len_timep)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_timep);
		ocalloc_size -= _len_timep;
	} else {
		ms->ms_timep = NULL;
	}

	ms->ms_t_len = t_len;
	status		 = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_gmtime_r(struct tm ** retval, const time_t * timep, int t_len, struct tm * tmp, int tmp_len)
{
	sgx_status_t status		= SGX_SUCCESS;
	size_t		 _len_timep = t_len;
	size_t		 _len_tmp	= tmp_len;

	ms_ocall_sgx_gmtime_r_t * ms		   = NULL;
	size_t					  ocalloc_size = sizeof(ms_ocall_sgx_gmtime_r_t);
	void *					  __tmp		   = NULL;

	void * __tmp_tmp = NULL;

	CHECK_ENCLAVE_POINTER(timep, _len_timep);
	CHECK_ENCLAVE_POINTER(tmp, _len_tmp);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timep != NULL) ? _len_timep : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tmp != NULL) ? _len_tmp : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_sgx_gmtime_r_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_gmtime_r_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_gmtime_r_t);

	if (timep != NULL) {
		ms->ms_timep = (const time_t *)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, timep, _len_timep)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_timep);
		ocalloc_size -= _len_timep;
	} else {
		ms->ms_timep = NULL;
	}

	ms->ms_t_len = t_len;
	if (tmp != NULL) {
		ms->ms_tmp = (struct tm *)__tmp;
		__tmp_tmp  = __tmp;
		memset(__tmp_tmp, 0, _len_tmp);
		__tmp = (void *)((size_t)__tmp + _len_tmp);
		ocalloc_size -= _len_tmp;
	} else {
		ms->ms_tmp = NULL;
	}

	ms->ms_tmp_len = tmp_len;
	status		   = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
		if (tmp) {
			if (memcpy_s((void *)tmp, _len_tmp, __tmp_tmp, _len_tmp)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_gettimeofday(int * retval, void * tv, int tv_size)
{
	sgx_status_t status	 = SGX_SUCCESS;
	size_t		 _len_tv = tv_size;

	ms_ocall_sgx_gettimeofday_t * ms		   = NULL;
	size_t						  ocalloc_size = sizeof(ms_ocall_sgx_gettimeofday_t);
	void *						  __tmp		   = NULL;

	void * __tmp_tv = NULL;

	CHECK_ENCLAVE_POINTER(tv, _len_tv);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tv != NULL) ? _len_tv : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_sgx_gettimeofday_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_gettimeofday_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_gettimeofday_t);

	if (tv != NULL) {
		ms->ms_tv = (void *)__tmp;
		__tmp_tv  = __tmp;
		if (memcpy_s(__tmp, ocalloc_size, tv, _len_tv)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_tv);
		ocalloc_size -= _len_tv;
	} else {
		ms->ms_tv = NULL;
	}

	ms->ms_tv_size = tv_size;
	status		   = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
		if (tv) {
			if (memcpy_s((void *)tv, _len_tv, __tmp_tv, _len_tv)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_getsockopt(int * retval, int s, int level, int optname, char * optval, int optval_len, int * optlen)
{
	sgx_status_t status		 = SGX_SUCCESS;
	size_t		 _len_optval = optval_len;
	size_t		 _len_optlen = 4;

	ms_ocall_sgx_getsockopt_t * ms			 = NULL;
	size_t						ocalloc_size = sizeof(ms_ocall_sgx_getsockopt_t);
	void *						__tmp		 = NULL;

	void * __tmp_optval = NULL;
	void * __tmp_optlen = NULL;

	CHECK_ENCLAVE_POINTER(optval, _len_optval);
	CHECK_ENCLAVE_POINTER(optlen, _len_optlen);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (optval != NULL) ? _len_optval : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (optlen != NULL) ? _len_optlen : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_sgx_getsockopt_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_getsockopt_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_getsockopt_t);

	ms->ms_s	   = s;
	ms->ms_level   = level;
	ms->ms_optname = optname;
	if (optval != NULL) {
		ms->ms_optval = (char *)__tmp;
		__tmp_optval  = __tmp;
		if (_len_optval % sizeof(*optval) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_optval, 0, _len_optval);
		__tmp = (void *)((size_t)__tmp + _len_optval);
		ocalloc_size -= _len_optval;
	} else {
		ms->ms_optval = NULL;
	}

	ms->ms_optval_len = optval_len;
	if (optlen != NULL) {
		ms->ms_optlen = (int *)__tmp;
		__tmp_optlen  = __tmp;
		if (_len_optlen % sizeof(*optlen) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, optlen, _len_optlen)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_optlen);
		ocalloc_size -= _len_optlen;
	} else {
		ms->ms_optlen = NULL;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
		if (optval) {
			if (memcpy_s((void *)optval, _len_optval, __tmp_optval, _len_optval)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (optlen) {
			if (memcpy_s((void *)optlen, _len_optlen, __tmp_optlen, _len_optlen)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_setsockopt(int * retval, int s, int level, int optname, const void * optval, int optlen)
{
	sgx_status_t status		 = SGX_SUCCESS;
	size_t		 _len_optval = optlen;

	ms_ocall_sgx_setsockopt_t * ms			 = NULL;
	size_t						ocalloc_size = sizeof(ms_ocall_sgx_setsockopt_t);
	void *						__tmp		 = NULL;


	CHECK_ENCLAVE_POINTER(optval, _len_optval);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (optval != NULL) ? _len_optval : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_sgx_setsockopt_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_setsockopt_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_setsockopt_t);

	ms->ms_s	   = s;
	ms->ms_level   = level;
	ms->ms_optname = optname;
	if (optval != NULL) {
		ms->ms_optval = (const void *)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, optval, _len_optval)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_optval);
		ocalloc_size -= _len_optval;
	} else {
		ms->ms_optval = NULL;
	}

	ms->ms_optlen = optlen;
	status		  = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_socket(int * retval, int af, int type, int protocol)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_socket_t * ms			 = NULL;
	size_t					ocalloc_size = sizeof(ms_ocall_sgx_socket_t);
	void *					__tmp		 = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_sgx_socket_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_socket_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_socket_t);

	ms->ms_af		= af;
	ms->ms_type		= type;
	ms->ms_protocol = protocol;
	status			= sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_listen(int * retval, int s, int backlog)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_listen_t * ms			 = NULL;
	size_t					ocalloc_size = sizeof(ms_ocall_sgx_listen_t);
	void *					__tmp		 = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_sgx_listen_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_listen_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_listen_t);

	ms->ms_s	   = s;
	ms->ms_backlog = backlog;
	status		   = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_bind(int * retval, int s, const void * addr, int addr_size)
{
	sgx_status_t status	   = SGX_SUCCESS;
	size_t		 _len_addr = addr_size;

	ms_ocall_sgx_bind_t * ms		   = NULL;
	size_t				  ocalloc_size = sizeof(ms_ocall_sgx_bind_t);
	void *				  __tmp		   = NULL;


	CHECK_ENCLAVE_POINTER(addr, _len_addr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_sgx_bind_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_bind_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_bind_t);

	ms->ms_s = s;
	if (addr != NULL) {
		ms->ms_addr = (const void *)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, addr, _len_addr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	ms->ms_addr_size = addr_size;
	status			 = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_connect(int * retval, int s, const void * addr, int addrlen)
{
	sgx_status_t status	   = SGX_SUCCESS;
	size_t		 _len_addr = addrlen;

	ms_ocall_sgx_connect_t * ms			  = NULL;
	size_t					 ocalloc_size = sizeof(ms_ocall_sgx_connect_t);
	void *					 __tmp		  = NULL;


	CHECK_ENCLAVE_POINTER(addr, _len_addr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_sgx_connect_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_connect_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_connect_t);

	ms->ms_s = s;
	if (addr != NULL) {
		ms->ms_addr = (const void *)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, addr, _len_addr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	ms->ms_addrlen = addrlen;
	status		   = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_accept(int * retval, int s, void * addr, int addr_size, int * addrlen)
{
	sgx_status_t status		  = SGX_SUCCESS;
	size_t		 _len_addr	  = addr_size;
	size_t		 _len_addrlen = 4;

	ms_ocall_sgx_accept_t * ms			 = NULL;
	size_t					ocalloc_size = sizeof(ms_ocall_sgx_accept_t);
	void *					__tmp		 = NULL;

	void * __tmp_addr	 = NULL;
	void * __tmp_addrlen = NULL;

	CHECK_ENCLAVE_POINTER(addr, _len_addr);
	CHECK_ENCLAVE_POINTER(addrlen, _len_addrlen);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addrlen != NULL) ? _len_addrlen : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_sgx_accept_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_accept_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_accept_t);

	ms->ms_s = s;
	if (addr != NULL) {
		ms->ms_addr = (void *)__tmp;
		__tmp_addr	= __tmp;
		memset(__tmp_addr, 0, _len_addr);
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	ms->ms_addr_size = addr_size;
	if (addrlen != NULL) {
		ms->ms_addrlen = (int *)__tmp;
		__tmp_addrlen  = __tmp;
		if (_len_addrlen % sizeof(*addrlen) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, addrlen, _len_addrlen)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addrlen);
		ocalloc_size -= _len_addrlen;
	} else {
		ms->ms_addrlen = NULL;
	}

	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
		if (addr) {
			if (memcpy_s((void *)addr, _len_addr, __tmp_addr, _len_addr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addrlen) {
			if (memcpy_s((void *)addrlen, _len_addrlen, __tmp_addrlen, _len_addrlen)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_shutdown(int * retval, int fd, int how)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_shutdown_t * ms		   = NULL;
	size_t					  ocalloc_size = sizeof(ms_ocall_sgx_shutdown_t);
	void *					  __tmp		   = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_sgx_shutdown_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_shutdown_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_shutdown_t);

	ms->ms_fd  = fd;
	ms->ms_how = how;
	status	   = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_read(int * retval, int fd, void * buf, int n)
{
	sgx_status_t status	  = SGX_SUCCESS;
	size_t		 _len_buf = n;

	ms_ocall_sgx_read_t * ms		   = NULL;
	size_t				  ocalloc_size = sizeof(ms_ocall_sgx_read_t);
	void *				  __tmp		   = NULL;

	void * __tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_sgx_read_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_read_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_read_t);

	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (void *)__tmp;
		__tmp_buf  = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	ms->ms_n = n;
	status	 = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void *)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_write(int * retval, int fd, const void * buf, int n)
{
	sgx_status_t status	  = SGX_SUCCESS;
	size_t		 _len_buf = n;

	ms_ocall_sgx_write_t * ms			= NULL;
	size_t				   ocalloc_size = sizeof(ms_ocall_sgx_write_t);
	void *				   __tmp		= NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_sgx_write_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_write_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_write_t);

	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (const void *)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	ms->ms_n = n;
	status	 = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_close(int * retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_close_t * ms			= NULL;
	size_t				   ocalloc_size = sizeof(ms_ocall_sgx_close_t);
	void *				   __tmp		= NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_sgx_close_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_close_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_close_t);

	ms->ms_fd = fd;
	status	  = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_getenv(int * retval, const char * env, int envlen, char * ret_str, int ret_len)
{
	sgx_status_t status		  = SGX_SUCCESS;
	size_t		 _len_env	  = envlen;
	size_t		 _len_ret_str = ret_len;

	ms_ocall_sgx_getenv_t * ms			 = NULL;
	size_t					ocalloc_size = sizeof(ms_ocall_sgx_getenv_t);
	void *					__tmp		 = NULL;

	void * __tmp_ret_str = NULL;

	CHECK_ENCLAVE_POINTER(env, _len_env);
	CHECK_ENCLAVE_POINTER(ret_str, _len_ret_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (env != NULL) ? _len_env : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ret_str != NULL) ? _len_ret_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_sgx_getenv_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_getenv_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_getenv_t);

	if (env != NULL) {
		ms->ms_env = (const char *)__tmp;
		if (_len_env % sizeof(*env) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, env, _len_env)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_env);
		ocalloc_size -= _len_env;
	} else {
		ms->ms_env = NULL;
	}

	ms->ms_envlen = envlen;
	if (ret_str != NULL) {
		ms->ms_ret_str = (char *)__tmp;
		__tmp_ret_str  = __tmp;
		if (_len_ret_str % sizeof(*ret_str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_ret_str, 0, _len_ret_str);
		__tmp = (void *)((size_t)__tmp + _len_ret_str);
		ocalloc_size -= _len_ret_str;
	} else {
		ms->ms_ret_str = NULL;
	}

	ms->ms_ret_len = ret_len;
	status		   = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
		if (ret_str) {
			if (memcpy_s((void *)ret_str, _len_ret_str, __tmp_ret_str, _len_ret_str)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(const char * str)
{
	sgx_status_t status	  = SGX_SUCCESS;
	size_t		 _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t * ms		   = NULL;
	size_t					  ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *					  __tmp		   = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_ocall_print_string_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char *)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status		  = SGX_SUCCESS;
	size_t		 _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t * ms		   = NULL;
	size_t				  ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *				  __tmp		   = NULL;

	void * __tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_sgx_oc_cpuidex_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int *)__tmp;
		__tmp_cpuinfo  = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}

	ms->ms_leaf	   = leaf;
	ms->ms_subleaf = subleaf;
	status		   = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void *)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int * retval, const void * self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t * ms			  = NULL;
	size_t										 ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *										 __tmp		  = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_sgx_thread_wait_untrusted_event_ocall_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status		= sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int * retval, const void * waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t * ms			 = NULL;
	size_t										ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *										__tmp		 = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_sgx_thread_set_untrusted_event_ocall_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status		  = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int * retval, const void * waiter, const void * self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t * ms			  = NULL;
	size_t											 ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *											 __tmp		  = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_sgx_thread_setwait_untrusted_events_ocall_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self	  = self;
	status		  = sgx_ocall(21, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int * retval, const void ** waiters, size_t total)
{
	sgx_status_t status		  = SGX_SUCCESS;
	size_t		 _len_waiters = total * sizeof(void *);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t * ms		   = NULL;
	size_t												  ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *												  __tmp		   = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms	  = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t *)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void **)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	ms->ms_total = total;
	status		 = sgx_ocall(22, ms);

	if (status == SGX_SUCCESS) {
		if (retval)
			*retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}
