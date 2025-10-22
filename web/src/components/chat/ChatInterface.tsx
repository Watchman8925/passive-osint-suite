import React, {
	useCallback,
	useEffect,
	useMemo,
	useRef,
	useState
} from 'react';
import axios, { AxiosError, AxiosInstance, AxiosRequestHeaders } from 'axios';
import ReactMarkdown from 'react-markdown';
import toast from 'react-hot-toast';
import clsx from 'clsx';
import { formatDistanceToNow } from 'date-fns';
import {
	Send,
	Loader2,
	Plus,
	Trash2,
	Download,
	Sparkles,
	RefreshCw,
	MessageSquare
} from 'lucide-react';
import apiClient, { AUTH_TOKEN_KEY } from '../../services/api';

type ConversationSummary = {
	id: string;
	title: string;
	created_at?: string;
	updated_at?: string;
	message_count?: number;
	investigation_id?: string | null;
	metadata?: Record<string, unknown>;
};

type ChatMessageRecord = {
	id: string;
	role: 'user' | 'assistant' | 'system';
	content: string;
	timestamp: string;
	metadata?: Record<string, unknown>;
	pending?: boolean;
	error?: string;
};

type ChatMode = 'parse' | 'execute';

interface ChatInterfaceProps {
	investigationId?: string | null;
	apiUrl?: string;
	onClose?: () => void;
	initialMode?: ChatMode;
}

interface FormattedResponse {
	text: string;
	metadata?: Record<string, unknown>;
}

interface AutopivotSuggestion {
	target: string;
	target_type?: string;
	reason?: string;
	confidence?: number;
	priority?: string;
	recommended_modules?: string[];
}

interface AutopivotResponse {
	pivot_suggestions?: AutopivotSuggestion[];
	count?: number;
	generated_at?: string;
}

export const FALLBACK_TITLE = 'New Conversation';

export function getErrorMessage(error: unknown): string {
	if (axios.isAxiosError(error)) {
		const axiosError = error as AxiosError<any>;
		const detail = axiosError.response?.data?.detail;
		const message = axiosError.response?.data?.message;
		if (typeof detail === 'string') return detail;
		if (typeof message === 'string') return message;
		if (axiosError.message) return axiosError.message;
	}
	if (error instanceof Error) {
		return error.message;
	}
	return 'Unexpected error occurred.';
}

export function formatTimestamp(timestamp: string | undefined): string {
	if (!timestamp) return '';
	try {
		return formatDistanceToNow(new Date(timestamp), { addSuffix: true });
	} catch (_) {
		return timestamp;
	}
}

export function formatNlpResponse(data: any, mode: ChatMode): FormattedResponse {
	if (!data) {
		return {
			text: 'No response received from the natural language processor.',
		};
	}

	if (mode === 'parse') {
		return {
			text: [
				'**Parsed Command**',
				`- Intent: \`${data.intent ?? 'unknown'}\``,
				`- Target Type: \`${data.target_type ?? 'unknown'}\``,
				data.target ? `- Target: \`${data.target}\`` : '- Target: _not detected_',
				data.modules?.length
					? `- Suggested Modules: ${data.modules.map((m: string) => `\`${m}\``).join(', ')}`
					: '- Suggested Modules: _none detected_',
				data.confidence !== undefined
					? `- Confidence: ${(Number(data.confidence) * 100).toFixed(1)}%`
					: '- Confidence: _not provided_',
				'\nYou can execute this command to run the recommended modules.'
			].join('\n'),
			metadata: data,
		};
	}

	if (data.status === 'low_confidence') {
		return {
			text: [
				'⚠️ **Low Confidence Interpretation**',
				data.message ?? 'The system could not confidently understand the command.',
				data.parsed
					? `\nParsed intent: \`${data.parsed.intent}\` for target \`${data.parsed.target ?? 'unknown'}\`.`
					: '',
				'\nTry rephrasing with more context.'
			].join('\n'),
			metadata: data,
		};
	}

	if (data.status === 'executed') {
		const modules = data.results ? Object.entries(data.results as Record<string, unknown>) : [];
		const rendered = modules.length
			? modules
					.map(([moduleName, result]) => `### ${moduleName}\n\n\
${'```json'}\n${JSON.stringify(result, null, 2)}\n${'```'}`)
					.join('\n\n')
			: '_No module output returned._';

		return {
			text: [
				'✅ **Command Executed Successfully**',
				`- Intent: \`${data.parsed?.intent ?? 'unknown'}\``,
				data.parsed?.target ? `- Target: \`${data.parsed.target}\`` : undefined,
				data.parsed?.modules?.length
					? `- Modules Run: ${data.parsed.modules.map((m: string) => `\`${m}\``).join(', ')}`
					: '- Modules Run: _not specified_',
				'',
				rendered,
			]
				.filter(Boolean)
				.join('\n'),
			metadata: data,
		};
	}

	return {
		text: `ℹ️ Received response:\n\n${'```json'}\n${JSON.stringify(data, null, 2)}\n${'```'}`,
		metadata: data,
	};
}

export function formatAutopivotResponse(data: AutopivotResponse): FormattedResponse {
	const suggestions = data?.pivot_suggestions ?? [];

		if (!suggestions.length) {
			return {
				text: 'No pivot suggestions were generated for this investigation.',
				metadata: { raw: data },
			};
		}

	const lines = suggestions.map((suggestion, index) => {
		const confidence = suggestion.confidence !== undefined
			? `${Math.round(Number(suggestion.confidence) * 100)}%`
			: 'n/a';
		const modules = suggestion.recommended_modules?.length
			? suggestion.recommended_modules.map(mod => `\`${mod}\``).join(', ')
			: '—';
		return [
			`**${index + 1}. ${suggestion.target}** (${suggestion.target_type ?? 'unknown'})`,
			suggestion.reason ? `Reason: ${suggestion.reason}` : undefined,
			`Confidence: ${confidence}`,
			`Priority: ${suggestion.priority ?? 'n/a'}`,
			`Recommended Modules: ${modules}`,
		]
			.filter(Boolean)
			.join('\n');
	});

		return {
			text: ['✨ **Autopivot Suggestions**', '', ...lines].join('\n'),
			metadata: { raw: data },
		};
}

function buildHttpClient(apiUrl?: string): AxiosInstance {
	if (!apiUrl) {
		return apiClient.client;
	}

        const instance = axios.create({
                baseURL: apiUrl,
                timeout: 45000,
                headers: { 'Content-Type': 'application/json' },
        });

        instance.interceptors.request.use((config) => {
                const token = localStorage.getItem(AUTH_TOKEN_KEY);
                if (token) {
									const headers = (config.headers ?? {}) as AxiosRequestHeaders;
									headers.Authorization = `Bearer ${token}`;
									config.headers = headers;
		}
		return config;
	});

        instance.interceptors.response.use(
                (response) => response,
                (error) => {
                        if (axios.isAxiosError(error) && error.response?.status === 401) {
                                localStorage.removeItem(AUTH_TOKEN_KEY);
                        }
                        return Promise.reject(error);
                }
        );

	return instance;
}

export const ChatInterface: React.FC<ChatInterfaceProps> = ({
	investigationId,
	apiUrl,
	onClose,
	initialMode = 'execute',
}) => {
	const http = useMemo(() => buildHttpClient(apiUrl), [apiUrl]);

	const [conversations, setConversations] = useState<ConversationSummary[]>([]);
	const [selectedConversationId, setSelectedConversationId] = useState<string | null>(null);
	const [messages, setMessages] = useState<ChatMessageRecord[]>([]);
	const [inputValue, setInputValue] = useState('');
	const [isSubmitting, setIsSubmitting] = useState(false);
	const [mode, setMode] = useState<ChatMode>(initialMode);
	const [pivotEnabled, setPivotEnabled] = useState(false);
	const [loadingConversations, setLoadingConversations] = useState(false);
	const [loadingMessages, setLoadingMessages] = useState(false);
	const [createTitle, setCreateTitle] = useState('');
	const [creatingConversation, setCreatingConversation] = useState(false);

	const messageContainerRef = useRef<HTMLDivElement | null>(null);
	const textareaRef = useRef<HTMLTextAreaElement | null>(null);

	const selectedConversation = useMemo(
		() => conversations.find((conv) => conv.id === selectedConversationId) ?? null,
		[conversations, selectedConversationId]
	);

	const scrollMessagesToBottom = useCallback(() => {
		if (messageContainerRef.current) {
			messageContainerRef.current.scrollTop = messageContainerRef.current.scrollHeight;
		}
	}, []);

	useEffect(() => {
		scrollMessagesToBottom();
	}, [messages, scrollMessagesToBottom]);

	const touchConversation = useCallback((conversationId: string, delta: number) => {
		setConversations((prev) => {
			const now = new Date().toISOString();
			return prev.map((conversation) =>
				conversation.id === conversationId
					? {
							...conversation,
							updated_at: now,
							message_count: (conversation.message_count ?? 0) + delta,
						}
					: conversation
			);
		});
	}, []);

	const fetchConversations = useCallback(async () => {
		setLoadingConversations(true);
		try {
			const { data } = await http.get('/api/chat/conversations', {
				params: { limit: 100, offset: 0 },
			});
			const list: ConversationSummary[] = data?.conversations ?? [];
			setConversations(list);
			if (!selectedConversationId && list.length > 0) {
				setSelectedConversationId(list[0].id);
			}
		} catch (error) {
			toast.error(`Failed to load conversations: ${getErrorMessage(error)}`);
		} finally {
			setLoadingConversations(false);
		}
	}, [http, selectedConversationId]);

	const fetchConversationMessages = useCallback(
		async (conversationId: string) => {
			setLoadingMessages(true);
			try {
				const { data } = await http.get(`/api/chat/conversations/${conversationId}`);
				const history: ChatMessageRecord[] = (data?.messages ?? []).map((message: any) => ({
					id: message.id,
					role: message.role ?? 'assistant',
					content: typeof message.content === 'string' ? message.content : JSON.stringify(message.content),
					timestamp: message.timestamp ?? new Date().toISOString(),
					metadata: message.metadata,
				}));
				setMessages(history);
			} catch (error) {
				setMessages([]);
				toast.error(`Unable to load conversation: ${getErrorMessage(error)}`);
			} finally {
				setLoadingMessages(false);
			}
		},
		[http]
	);

	const createConversation = useCallback(async () => {
		const title = createTitle.trim() || FALLBACK_TITLE;
		setCreatingConversation(true);
		try {
			const { data } = await http.post('/api/chat/conversations', {
				investigation_id: investigationId ?? undefined,
				title,
			});

			const newConversation: ConversationSummary = {
				id: data?.conversation_id,
				title: data?.title ?? title,
				created_at: data?.created_at,
				updated_at: data?.created_at,
				investigation_id: data?.investigation_id ?? investigationId ?? null,
				message_count: 0,
			};

			setConversations((prev) => [newConversation, ...prev]);
			setSelectedConversationId(newConversation.id);
			setMessages([]);
			setCreateTitle('');
			toast.success('Conversation created');
			return newConversation.id;
		} catch (error) {
			toast.error(`Failed to create conversation: ${getErrorMessage(error)}`);
			throw error;
		} finally {
			setCreatingConversation(false);
		}
	}, [http, investigationId, createTitle]);

	const ensureConversation = useCallback(async () => {
		if (selectedConversationId) {
			return selectedConversationId;
		}
		return createConversation();
	}, [selectedConversationId, createConversation]);

		const saveMessage = useCallback(
			async (
				conversationId: string,
				message: { role: 'user' | 'assistant' | 'system'; content: string; metadata?: Record<string, unknown> }
			): Promise<string | null> => {
			try {
				const { data } = await http.post('/api/chat/messages', {
					conversation_id: conversationId,
					role: message.role,
					content: message.content,
					metadata: message.metadata ?? {},
				});
				return data?.message_id ?? null;
			} catch (error) {
				toast.error(`Failed to save message: ${getErrorMessage(error)}`);
				return null;
			}
		},
		[http]
	);

	const handleSend = useCallback(async () => {
		const content = inputValue.trim();
		if (!content || isSubmitting) {
			return;
		}

		setIsSubmitting(true);
		setInputValue('');

		let conversationId: string;
		try {
			conversationId = await ensureConversation();
		} catch (_) {
			setIsSubmitting(false);
			setInputValue(content);
			return;
		}

		const timestamp = new Date().toISOString();
		const localUserId = `local-user-${timestamp}`;
		const userMessage: ChatMessageRecord = {
			id: localUserId,
			role: 'user',
			content,
			timestamp,
			metadata: { mode, pivotEnabled },
			pending: true,
		};

		setMessages((prev) => [...prev, userMessage]);
		touchConversation(conversationId, 1);

			const persistedUserId = await saveMessage(conversationId, {
				role: userMessage.role,
				content: userMessage.content,
				metadata: userMessage.metadata,
			});

		setMessages((prev) =>
			prev.map((message) =>
				message.id === localUserId
					? {
							...message,
							id: persistedUserId ?? message.id,
							pending: false,
						}
					: message
			)
		);

		try {
			const endpoint = mode === 'parse' ? '/api/nlp/parse' : '/api/nlp/execute';
			const { data } = await http.post(endpoint, {
				command: content,
				investigation_id: investigationId ?? undefined,
				execute: mode === 'execute',
			});

			const formatted = formatNlpResponse(data, mode);
			const assistantTimestamp = new Date().toISOString();
			const assistantLocalId = `local-assistant-${assistantTimestamp}`;
			const assistantMessage: ChatMessageRecord = {
				id: assistantLocalId,
				role: 'assistant',
				content: formatted.text,
				timestamp: assistantTimestamp,
				metadata: { ...(formatted.metadata ?? {}), source: endpoint },
			};

			setMessages((prev) => [...prev, assistantMessage]);
			touchConversation(conversationId, 1);

					const savedAssistantId = await saveMessage(conversationId, {
						role: assistantMessage.role,
						content: assistantMessage.content,
						metadata: assistantMessage.metadata,
					});

			if (savedAssistantId) {
				setMessages((prev) =>
					prev.map((message) =>
						message.id === assistantLocalId
							? {
									...message,
									id: savedAssistantId,
								}
							: message
					)
				);
			}

			if (pivotEnabled) {
				if (!investigationId) {
					toast.error('Select an investigation to request autopivot suggestions.');
				} else {
					try {
						const { data: pivotData } = await http.post('/api/autopivot/suggest', {
							investigation_id: investigationId,
							max_pivots: 5,
						});

						const pivotFormatted = formatAutopivotResponse(pivotData);
						const pivotTimestamp = new Date().toISOString();
						const pivotLocalId = `local-pivot-${pivotTimestamp}`;
						const pivotMessage: ChatMessageRecord = {
							id: pivotLocalId,
							role: 'assistant',
							content: pivotFormatted.text,
							timestamp: pivotTimestamp,
							metadata: { ...(pivotFormatted.metadata ?? {}), source: 'autopivot' },
						};

						setMessages((prev) => [...prev, pivotMessage]);
						touchConversation(conversationId, 1);

									const savedPivotId = await saveMessage(conversationId, {
										role: pivotMessage.role,
										content: pivotMessage.content,
										metadata: pivotMessage.metadata,
									});

						if (savedPivotId) {
							setMessages((prev) =>
								prev.map((message) =>
									message.id === pivotLocalId
										? {
												...message,
												id: savedPivotId,
											}
										: message
								)
							);
						}
					} catch (pivotError) {
						const message = getErrorMessage(pivotError);
						toast.error(`Autopivot failed: ${message}`);
						const pivotErrorMessage: ChatMessageRecord = {
							id: `autopivot-error-${Date.now()}`,
							role: 'assistant',
							content: `⚠️ Autopivot request failed.\n\n${message}`,
							timestamp: new Date().toISOString(),
							metadata: { error: message, source: 'autopivot' },
						};
						setMessages((prev) => [...prev, pivotErrorMessage]);
						touchConversation(conversationId, 1);
					}
				}
			}
		} catch (error) {
			const message = getErrorMessage(error);
			const errorMessage: ChatMessageRecord = {
				id: `assistant-error-${Date.now()}`,
				role: 'assistant',
				content: `⚠️ Unable to process command.\n\n${message}`,
				timestamp: new Date().toISOString(),
				metadata: { error: message, source: 'nlp' },
			};
			setMessages((prev) => [...prev, errorMessage]);
			touchConversation(conversationId, 1);
		} finally {
			setIsSubmitting(false);
			setTimeout(() => {
				textareaRef.current?.focus();
			}, 150);
		}
	}, [
		inputValue,
		isSubmitting,
		ensureConversation,
		http,
		investigationId,
		mode,
		pivotEnabled,
		saveMessage,
		touchConversation,
	]);

	const handleDeleteConversation = useCallback(
		async (conversationId: string) => {
			if (!window.confirm('Delete this conversation? This cannot be undone.')) {
				return;
			}
			try {
				await http.delete(`/api/chat/conversations/${conversationId}`);
				setConversations((prev) => prev.filter((conversation) => conversation.id !== conversationId));
				if (selectedConversationId === conversationId) {
					setSelectedConversationId(null);
					setMessages([]);
				}
				toast.success('Conversation deleted');
			} catch (error) {
				toast.error(`Failed to delete conversation: ${getErrorMessage(error)}`);
			}
		},
		[http, selectedConversationId]
	);

	const handleExport = useCallback(
		async (conversationId: string, format: 'json' | 'markdown') => {
			try {
				const { data } = await http.get(`/api/chat/conversations/${conversationId}/export`, {
					params: { format },
					responseType: 'blob',
				});

				const blob = new Blob([data], {
					type: format === 'json' ? 'application/json' : 'text/markdown',
				});

				const url = window.URL.createObjectURL(blob);
				const link = document.createElement('a');
				link.href = url;
				const filename = `${conversationId}-${new Date().toISOString().slice(0, 19)}.${format === 'json' ? 'json' : 'md'}`;
				link.setAttribute('download', filename);
				document.body.appendChild(link);
				link.click();
				document.body.removeChild(link);
				window.URL.revokeObjectURL(url);
				toast.success('Conversation export started');
			} catch (error) {
				toast.error(`Failed to export conversation: ${getErrorMessage(error)}`);
			}
		},
		[http]
	);

	const handleRefresh = useCallback(() => {
		if (selectedConversationId) {
			fetchConversationMessages(selectedConversationId);
		} else {
			fetchConversations();
		}
	}, [fetchConversationMessages, fetchConversations, selectedConversationId]);

	useEffect(() => {
		fetchConversations();
	}, [fetchConversations]);

	useEffect(() => {
		if (selectedConversationId) {
			fetchConversationMessages(selectedConversationId);
		} else {
			setMessages([]);
		}
	}, [selectedConversationId, fetchConversationMessages]);

	return (
		<div className="flex h-full w-full flex-col gap-6 rounded-2xl border border-slate-200/60 bg-white/80 p-6 shadow-xl backdrop-blur-xl">
			<div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
				<div>
					<h2 className="flex items-center gap-2 text-xl font-semibold text-slate-900">
						<MessageSquare className="h-5 w-5 text-blue-600" />
						AI Assistant
					</h2>
					<p className="text-sm text-slate-500">
						Natural language command center with conversation history and autopivot support.
					</p>
				</div>
				<div className="flex flex-wrap items-center gap-3">
					<div className="flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1 text-xs text-slate-600 shadow-sm">
						<span>Mode:</span>
						<button
							type="button"
							onClick={() => setMode('parse')}
							className={clsx(
								'rounded-full px-3 py-1 font-medium transition-colors',
								mode === 'parse'
									? 'bg-blue-600 text-white shadow'
									: 'bg-slate-100 text-slate-600 hover:bg-slate-200'
							)}
						>
							Parse
						</button>
						<button
							type="button"
							onClick={() => setMode('execute')}
							className={clsx(
								'rounded-full px-3 py-1 font-medium transition-colors',
								mode === 'execute'
									? 'bg-blue-600 text-white shadow'
									: 'bg-slate-100 text-slate-600 hover:bg-slate-200'
							)}
						>
							Execute
						</button>
					</div>
					<label className="flex items-center gap-2 text-xs font-medium text-slate-600">
						<input
							type="checkbox"
							className="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
							checked={pivotEnabled}
							onChange={(event) => setPivotEnabled(event.target.checked)}
						/>
						<span className="flex items-center gap-1">
							<Sparkles className="h-4 w-4 text-violet-500" /> Autopivot
						</span>
					</label>
					<button
						type="button"
						onClick={handleRefresh}
						className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-medium text-slate-600 shadow-sm transition hover:border-blue-200 hover:text-blue-600"
					>
						<RefreshCw className="h-4 w-4" /> Refresh
					</button>
					{onClose && (
						<button
							type="button"
							onClick={onClose}
							className="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-medium text-slate-600 shadow-sm transition hover:border-red-200 hover:text-red-500"
						>
							Close
						</button>
					)}
				</div>
			</div>

			<div className="flex flex-1 flex-col gap-6 lg:flex-row">
				<aside className="flex w-full flex-col gap-4 rounded-2xl border border-slate-200 bg-white/90 p-4 shadow lg:w-72">
					<div className="flex items-center justify-between">
						<h3 className="text-sm font-semibold text-slate-700">Conversations</h3>
						<button
							type="button"
							onClick={() => createConversation().catch(() => undefined)}
							disabled={creatingConversation}
										aria-label="Create conversation"
							className="inline-flex items-center justify-center rounded-full border border-blue-200 bg-blue-50 p-2 text-blue-600 shadow-sm transition hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-60"
						>
							{creatingConversation ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
						</button>
					</div>
					<div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
						<label className="text-xs font-medium text-slate-600" htmlFor="conversation-title">
							Title for new conversation
						</label>
						<input
							id="conversation-title"
							type="text"
							value={createTitle}
							onChange={(event) => setCreateTitle(event.target.value)}
							placeholder="e.g. Domain recon"
							className="mt-1 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-200"
						/>
					</div>
					<div className="flex-1 overflow-y-auto pr-1">
						{loadingConversations ? (
							<div className="flex h-full items-center justify-center text-sm text-slate-500">
								<Loader2 className="mr-2 h-4 w-4 animate-spin" /> Loading conversations...
							</div>
						) : conversations.length === 0 ? (
							<div className="rounded-xl border border-dashed border-slate-300 p-4 text-center text-xs text-slate-500">
								No conversations yet. Create one to get started.
							</div>
						) : (
							<ul className="flex flex-col gap-2">
								{conversations.map((conversation) => {
									const isActive = conversation.id === selectedConversationId;
									return (
										<li key={conversation.id}>
											<div
												role="button"
												tabIndex={0}
												onClick={() => setSelectedConversationId(conversation.id)}
												onKeyDown={(event) => {
													if (event.key === 'Enter' || event.key === ' ' || event.key === 'Spacebar') {
														event.preventDefault();
														setSelectedConversationId(conversation.id);
													}
												}}
												className={clsx(
													'w-full rounded-xl border px-3 py-3 text-left text-sm transition focus:outline-none focus:ring-2 focus:ring-blue-300',
													isActive
														? 'border-blue-300 bg-blue-50 text-blue-700 shadow'
														: 'border-slate-200 bg-white text-slate-700 hover:border-blue-200 hover:bg-blue-50/60'
												)}
											>
												<div className="flex items-center justify-between gap-2">
													<span className="font-semibold">
														{conversation.title || FALLBACK_TITLE}
													</span>
													<span className="rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-semibold text-slate-500">
														{conversation.message_count ?? 0}
													</span>
												</div>
												<div className="mt-1 text-[11px] text-slate-500">
													{formatTimestamp(conversation.updated_at)}
												</div>
												{conversation.investigation_id && (
													<div className="mt-2 text-[10px] uppercase tracking-wide text-blue-500">
														Linked Investigation: {conversation.investigation_id}
													</div>
												)}
												<div className="mt-2 flex items-center justify-between text-[11px] text-slate-500">
													<button
														type="button"
														onClick={(event) => {
															event.stopPropagation();
															handleExport(conversation.id, 'markdown');
														}}
														aria-label={`Export ${conversation.title || FALLBACK_TITLE} conversation as Markdown`}
														className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-[11px] font-medium text-blue-600 hover:bg-blue-100"
													>
														<Download className="h-3 w-3" /> MD
													</button>
													<button
														type="button"
														onClick={(event) => {
															event.stopPropagation();
															handleExport(conversation.id, 'json');
														}}
														aria-label={`Export ${conversation.title || FALLBACK_TITLE} conversation as JSON`}
														className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-[11px] font-medium text-slate-600 hover:bg-slate-100"
													>
														<Download className="h-3 w-3" /> JSON
													</button>
													<button
														type="button"
														onClick={(event) => {
															event.stopPropagation();
															handleDeleteConversation(conversation.id);
														}}
														aria-label={`Delete ${conversation.title || FALLBACK_TITLE}`}
														className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-[11px] font-medium text-red-500 hover:bg-red-100"
													>
														<Trash2 className="h-3 w-3" /> Delete
													</button>
												</div>
											</div>
										</li>
									);
								})}
							</ul>
						)}
					</div>
				</aside>

				<section className="flex h-full flex-1 flex-col gap-4">
					<div className="flex items-center justify-between rounded-2xl border border-slate-200 bg-white/90 px-5 py-3 shadow">
						<div>
							<h3 className="text-sm font-semibold text-slate-700">
								{selectedConversation?.title || FALLBACK_TITLE}
							</h3>
							<p className="text-xs text-slate-500">
								{selectedConversation?.updated_at
									? `Updated ${formatTimestamp(selectedConversation.updated_at)}`
									: 'No messages yet'}
							</p>
						</div>
						<div className="text-right">
							<p className="text-[11px] uppercase tracking-wide text-slate-400">
								{mode === 'execute' ? 'Execution Mode' : 'Parse Mode'}
							</p>
							{pivotEnabled && (
								<p className="text-[11px] text-violet-500">Autopivot enabled</p>
							)}
						</div>
					</div>

					<div
						ref={messageContainerRef}
						className="flex-1 overflow-y-auto rounded-2xl border border-slate-200 bg-white/80 p-4 shadow-inner"
					>
						{loadingMessages ? (
							<div className="flex h-full items-center justify-center text-sm text-slate-500">
								<Loader2 className="mr-2 h-4 w-4 animate-spin" /> Loading messages...
							</div>
						) : messages.length === 0 ? (
							<div className="flex h-full flex-col items-center justify-center gap-2 text-center text-sm text-slate-500">
								<MessageSquare className="h-10 w-10 text-blue-300" />
								<p>No messages yet. Send a command to get started.</p>
							</div>
						) : (
							<div className="flex flex-col gap-3">
								{messages.map((message) => (
									<div
										key={message.id}
										className={clsx(
											'flex w-full',
											message.role === 'user' ? 'justify-end' : 'justify-start'
										)}
									>
										<div
											className={clsx(
												'max-w-2xl rounded-2xl border px-4 py-3 shadow-sm',
												message.role === 'user'
													? 'border-blue-200 bg-gradient-to-br from-blue-600 to-indigo-600 text-white'
													: 'border-slate-200 bg-white text-slate-800'
											)}
										>
											{message.role === 'assistant' ? (
												<ReactMarkdown className="prose prose-sm max-w-none text-slate-800">
													{message.content}
												</ReactMarkdown>
											) : (
												<p className="whitespace-pre-wrap text-sm leading-relaxed">
													{message.content}
												</p>
											)}
											<div className="mt-2 flex items-center gap-2 text-[11px] text-slate-400">
												{message.pending && <Loader2 className="h-3 w-3 animate-spin" />}
												<span>{formatTimestamp(message.timestamp)}</span>
											</div>
											{message.error && (
												<div className="mt-2 rounded-lg border border-red-200 bg-red-50 p-2 text-xs text-red-600">
													{message.error}
												</div>
											)}
										</div>
									</div>
								))}
							</div>
						)}
					</div>

					<div className="rounded-2xl border border-slate-200 bg-white/90 p-4 shadow">
						<div className="mb-2 flex items-center justify-between text-xs text-slate-500">
							<span>
								Shift+Enter to add a new line. Enter to send.
							</span>
							{investigationId ? (
								<span className="font-medium text-blue-600">
									Linked investigation: {investigationId}
								</span>
							) : (
								<span className="text-slate-400">
									No linked investigation.
								</span>
							)}
						</div>
						<textarea
							ref={textareaRef}
							value={inputValue}
							onChange={(event) => setInputValue(event.target.value)}
							onKeyDown={(event) => {
								if (event.key === 'Enter' && !event.shiftKey) {
									event.preventDefault();
									handleSend();
								}
							}}
							rows={3}
							placeholder={
								mode === 'execute'
									? 'Describe what you want to investigate...'
									: 'Ask the assistant to interpret your intent...'
							}
							className="w-full resize-none rounded-xl border border-slate-300 bg-white px-3 py-3 text-sm text-slate-700 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-200"
						/>
						<div className="mt-3 flex items-center justify-between">
							<div className="text-xs text-slate-400">
								{pivotEnabled && !investigationId
									? 'Autopivot requires a selected investigation.'
									: '\u00A0'}
							</div>
							<button
								type="button"
								onClick={handleSend}
								disabled={!inputValue.trim() || isSubmitting}
								className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 px-5 py-2 text-sm font-semibold text-white shadow transition hover:from-blue-500 hover:to-indigo-500 disabled:cursor-not-allowed disabled:opacity-60"
							>
								{isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
								{isSubmitting ? 'Processing' : 'Send'}
							</button>
						</div>
					</div>
				</section>
			</div>
		</div>
	);
};

export default ChatInterface;
