import { z } from 'zod';

export const taskSchema = z.object({
  id: z.string(),
  name: z.string().optional(),
  task_type: z.string().optional(),
  status: z.string(),
  progress: z.number().min(0).max(100).optional(),
  started_at: z.string().optional(),
  completed_at: z.string().optional(),
  error: z.string().optional()
});

export const investigationUpdateSchema = z.object({
  type: z.literal('investigation_update'),
  investigation_id: z.string(),
  data: z.record(z.any()).optional()
});

export const taskUpdateSchema = z.object({
  type: z.union([
    z.literal('task_update'),
    z.literal('task_completed'),
    z.literal('task_failed')
  ]),
  investigation_id: z.string(),
  data: z.object({ task: taskSchema.partial().extend({ id: z.string() }) }).or(taskSchema).optional()
});

export const genericMessageSchema = z.object({
  type: z.string(),
  investigation_id: z.string().optional(),
  data: z.any().optional()
});

export const wsMessageSchema = z.union([
  investigationUpdateSchema,
  taskUpdateSchema,
  genericMessageSchema
]);

export type WSMessage = z.infer<typeof wsMessageSchema>;
