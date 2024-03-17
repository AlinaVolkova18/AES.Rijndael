using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Reflection.Metadata.Ecma335;
using System.Text.Json.Serialization;

namespace Rijndael
{
	internal class Program
	{

		private static Byte[] _sBox = {
			0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
			0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
			0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
			0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
			0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
			0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
			0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
			0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
			0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
			0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
			0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
			0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
			0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
			0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
			0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
			0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
		};

		private static Byte[] _inversedSBox = {
			0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
			0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
			0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
			0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
			0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
			0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
			0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
			0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
			0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
			0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
			0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
			0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
			0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
			0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
			0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
			0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
		};

		private static Byte[,] _cTable = {
			{ 2, 3, 1, 1 },
			{ 1, 2, 3, 1 },
			{ 1, 1, 2, 3 },
			{ 3, 1, 1, 2 },
		};

		private static Byte[,] _inversedCTable = {
			{ 14, 11, 13, 9 },
			{ 9, 14, 11, 13 },
			{ 13, 9, 14, 11 },
			{ 11, 13, 9, 14 },
		};

		private static int[,] _roundsTable = {
			{ 10, 12, 14 },
			{ 12, 12, 14 },
			{ 14, 14, 14 },
		};

		private static int[,] _shiftTable = {
			{ 1, 2, 3 },
			{ 1, 2, 3 },
			{ 1, 3, 4 },
		};

		private static UInt32[] _rconValues = {
			0x01000000,
			0x02000000,
			0x04000000,
			0x08000000,
			0x10000000,
			0x20000000,
			0x40000000,
			0x80000000,
			0x1B000000,
			0x36000000,
			0x6C000000,
		};


		static void Main(string[] args)
		{

			Byte[] key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

			EncodeFile("plain.txt", key);
			DecodeFile("encryption.txt", key);
		}


		private static void EncodeFile(String fileName, Byte[] key)
		{
			using var binaryReader = new BinaryReader(File.OpenRead(fileName)); // для считывания данных из файла
			using var binaryWriter = new BinaryWriter(File.OpenWrite("encryption.txt")); // для записи данных в файл

			int blocksCount = (int)(binaryReader.BaseStream.Length / 16); // количество блоков по 16 байт

			for (int i = 0; i < blocksCount; i++)
			{
				Byte[] currentBlock = binaryReader.ReadBytes(16); // считываем 16 байт из исходного файла
				Byte[] encoded = EncodeData(currentBlock, key); // шифруем данные по ключу

				binaryWriter.Write(encoded); // записываем зашифрованные данные в файл
			}
		}

		private static void DecodeFile(String fileName, Byte[] key)
		{
			using var binaryReader = new BinaryReader(File.OpenRead(fileName));
			using var binaryWriter = new BinaryWriter(File.OpenWrite("decryption.txt"));

			int blocksCount = (int)(binaryReader.BaseStream.Length / 16);

			for (int i = 0; i < blocksCount; i++)
			{
				Byte[] currentBlock = binaryReader.ReadBytes(16);
				Byte[] decoded = DecodeData(currentBlock, key);

				binaryWriter.Write(decoded);
			}
		}


		private static Byte[] EncodeData(Byte[] sourceData, Byte[] key)
		{
			Block sourceBlock = ConvertByteArrayToBlock(sourceData); // конвертируем 16 байт в объект Block, в котором данные хранятся в двумерном массиве 4х4
			Block[] keys = KeyExpansion(sourceBlock.Columns, key); // расширяем исходный ключ до 11 ключей (исходный + 10 ключей для каждого раунда)
			int rounds = 10;

			AddRoundKey(sourceBlock, keys[0]); // нулевой раунд

			for (int i = 0; i < rounds - 1; i++)
			{ // 10 раундов
				ByteSub(sourceBlock); // операция в которой каждый элемент пропускается через таблицу SBox
				ShiftRow(sourceBlock); // сдвиг строк
				MixColumn(sourceBlock); // матричное умножение столбцов
				AddRoundKey(sourceBlock, keys[i + 1]); // добавляем к каждому элементу значение ключ с помощью операции XOR
			}

			// последний раунд
			ByteSub(sourceBlock);
			ShiftRow(sourceBlock);
			AddRoundKey(sourceBlock, keys[rounds]);

			return ConvertBlockToByteArray(sourceBlock); // конвертируем блок обратно в массив байтов
		}

		private static Byte[] DecodeData(Byte[] sourceData, Byte[] key)
		{ // по факту то же самое
			Block sourceBlock = ConvertByteArrayToBlock(sourceData);
			Block[] keys = KeyExpansion(sourceBlock.Columns, key);
			int rounds = 10;

			AddRoundKey(sourceBlock, keys[rounds]);

			for (int i = rounds - 1; i > 0; i--)
			{ // но ключи берутся в обратном порядке
				InversedByteSub(sourceBlock); // все операции кроме AddRoundKey являются инверсированными
				InversedShiftRow(sourceBlock);
				AddRoundKey(sourceBlock, keys[i]);
				InversedMixColumn(sourceBlock); // и тут сначала идёт AddRoundKey, а потом MixColumn
			}

			InversedByteSub(sourceBlock);
			InversedShiftRow(sourceBlock);
			AddRoundKey(sourceBlock, keys[0]);

			return ConvertBlockToByteArray(sourceBlock);
		}



		private static Block ConvertByteArrayToBlock(Byte[] byteArray)
		{
			Block block = new Block(byteArray.Length / 4);

			// здесь мы обычный массив из 16 элементов раскладываем в матрицу 4х4
			// причём по вертикали, т.е. если взять массив
			// 0, 1, 2, 3, 4, 5, 6, ..., 13, 14, 15
			// то матрица будет:
			// 0 4  .. ..
			// 1 5  .. 13
			// 2 6  .. 14
			// 3 .. .. 15
			for (int i = 0; i < block.Rows; i++)
				for (int j = 0; j < block.Columns; j++)
					block.Bytes[i, j] = byteArray[j * block.Columns + i];

			return block;
		}

		private static Byte[] ConvertBlockToByteArray(Block block)
		{
			Byte[] byteArray = new Byte[block.Rows * block.Columns];

			for (int i = 0; i < block.Rows; i++)
				for (int j = 0; j < block.Columns; j++)
					byteArray[j * block.Columns + i] = block.Bytes[i, j];

			return byteArray;
		}


		private static void ByteSub(Block block)
		{
			for (int i = 0; i < block.Rows; i++)
				for (int j = 0; j < block.Columns; j++)
					block.Bytes[i, j] = _sBox[block.Bytes[i, j]]; // применяем SBox для каждого элемента
		}

		private static void InversedByteSub(Block block)
		{
			for (int i = 0; i < block.Rows; i++)
				for (int j = 0; j < block.Columns; j++)
					block.Bytes[i, j] = _inversedSBox[block.Bytes[i, j]]; // применяем инверсированный SBox для каждого элемента
		}


		private static void ShiftRow(Block block)
		{
			for (int i = 1; i < block.Rows; i++)
				block.ShiftRowToLeft(i, _shiftTable[(block.Columns - 4) / 2, i - 1]); // сдвигаем строки влево, i-ая строка сдвигается на i элементов
		}

		private static void InversedShiftRow(Block block)
		{
			for (int i = 1; i < block.Rows; i++)
				block.ShiftRowToLeft(i, block.Columns - _shiftTable[(block.Columns - 4) / 2, i - 1]);
		}


		private static void MixColumn(Block block)
		{
			for (int column = 0; column < block.Columns; column++)
			{
				Byte[] newColumn = new Byte[block.Rows];

				for (int row = 0; row < block.Rows; row++)
				{
					Byte newValue = 0;

					for (int i = 0; i < block.Rows; i++)
						newValue ^= gmul(block.Bytes[i, column], _cTable[row, i]); // тут идёт матричное умножение каждого столбца на константу C[i], причём вместо сложения (как в обычном умножении) используется XOR

					newColumn[row] = newValue;
				}

				for (int row = 0; row < block.Rows; row++)
					block.Bytes[row, column] = newColumn[row];
			}
		}

		private static void InversedMixColumn(Block block)
		{
			for (int column = 0; column < block.Columns; column++)
			{
				Byte[] newColumn = new Byte[block.Rows];

				for (int row = 0; row < block.Rows; row++)
				{
					Byte newValue = 0;

					for (int i = 0; i < block.Rows; i++)
						newValue ^= gmul(block.Bytes[i, column], _inversedCTable[row, i]); // здесь просто используем другие коэффициенты C[i] (инверсированные)

					newColumn[row] = newValue;
				}

				for (int row = 0; row < block.Rows; row++)
					block.Bytes[row, column] = newColumn[row];
			}
		}

		private static byte gmul(byte a, byte b)
		{ // сам хз как это работает, просто спиздил с методы
			byte p = 0;
			bool hi_bit_set;
			for (int counter = 0; counter < 8; counter++)
			{
				if ((b & 1) == 1)
					p ^= a;
				hi_bit_set = (a & 0x80) != 0;
				a <<= 1;
				if (hi_bit_set)
					a ^= 0x1b;   /* x^8 + x^4 + x^3 + x + 1 */
				b >>= 1;
			}
			return p;
		}


		private static void AddRoundKey(Block block, Block key)
		{ // здесь к каждому элементу блока ксорится элемент ключа
			for (int row = 0; row < block.Rows; row++)
				for (int column = 0; column < block.Columns; column++)
					block.Bytes[row, column] ^= key.Bytes[row, column];
		}



		private static Block[] KeyExpansion(int blockSize, Byte[] sourceKey)
		{ // метод расширения исходного ключа в 11 ключей

			int Nk = sourceKey.Length / 4;
			int rounds = _roundsTable[(Nk - 4) / 2, (blockSize - 4) / 2];
			List<UInt32> words = new List<UInt32>(blockSize * rounds + Nk); // будем работать с 32-битными словами
			Block[] blocks = new Block[rounds + 1];

			for (int i = 0; i < Nk; i++)
			{ // записываем в words первый ключ
				words.Add(
					CombineBytesToUInt32(
						sourceKey[i * 4],
						sourceKey[i * 4 + 1],
						sourceKey[i * 4 + 2],
						sourceKey[i * 4 + 3]
					)
				);
			}

			for (int i = Nk; i < words.Capacity; i++)
			{ 
				UInt32 temp = words[i - 1];

				if (i % Nk == 0)
					temp = SubWord(RotWord(temp)) ^ _rconValues[i / Nk - 1];

				words.Add(words[i - Nk] ^ temp);
			}

			for (int i = 0; i < blocks.Length; i++)
				blocks[i] = ConvertWordsToBlock(words.GetRange(i * 4, 4).ToArray()); // конвертируем 32-битные слова в блоки ключей

			return blocks;
		}

		private static UInt32 SubWord(UInt32 word)
		{
			return CombineBytesToUInt32( // здесь мы каждый байт слова пропускаем через SBox и соединяем заново в 32-битное слово
				_sBox[GetByteFromWord(word, 0)],
				_sBox[GetByteFromWord(word, 1)],
				_sBox[GetByteFromWord(word, 2)],
				_sBox[GetByteFromWord(word, 3)]
			);
		}

		private static Byte GetByteFromWord(UInt32 word, int index)
		{
			int mask = (24 - index * 8);
			return (Byte)((word >> mask) & 0xFF);
		}

		private static UInt32 RotWord(UInt32 word)
		{ // здесь просто сдвигаем биты циклически на 1 байт
			return (word << 8) | (word >> (32 - 8));
		}


		private static Block ConvertWordsToBlock(UInt32[] words)
		{
			Block block = new Block(words.Length);

			for (int i = 0; i < words.Length; i++)
				SplitUInt32ToBytes(
					words[i],
					out block.Bytes[0, i],
					out block.Bytes[1, i],
					out block.Bytes[2, i],
					out block.Bytes[3, i]
				);

			return block;
		}

		private static void SplitUInt32ToBytes(UInt32 value, out Byte first, out Byte second, out Byte third, out Byte fourth)
		{
			first = (Byte)((value >> 24) & 0xFF);
			second = (Byte)((value >> 16) & 0xFF);
			third = (Byte)((value >> 8) & 0xFF);
			fourth = (Byte)(value & 0xFF);
		}

		private static UInt32 CombineBytesToUInt32(Byte first, Byte second, Byte third, Byte fourth)
		{
			return (UInt32)first << 24
				| (UInt32)second << 16
				| (UInt32)third << 8
				| (UInt32)fourth;
		}
	}
}